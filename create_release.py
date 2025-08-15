#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import datetime
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.parse import urlparse


def parse_content_disposition_filename(header_value: Optional[str]) -> Optional[str]:
    """Extract filename from a Content-Disposition header value if present."""
    if not header_value:
        return None
    # Try to find filename*= (RFC 5987) first
    m = re.search(r"filename\*=(?:UTF-8''|)([^;]+)", header_value, flags=re.IGNORECASE)
    if m:
        candidate = m.group(1).strip().strip('"')
        return candidate
    # Fallback to filename=
    m = re.search(r"filename=([^;]+)", header_value, flags=re.IGNORECASE)
    if m:
        candidate = m.group(1).strip().strip('"')
        return candidate
    return None


def infer_filename_from_response(response, requested_url: str) -> str:
    """Infer a sensible filename from HTTP response headers or the final URL."""
    cd = response.headers.get('Content-Disposition')
    name = parse_content_disposition_filename(cd)
    if name:
        return os.path.basename(name)
    # Use final URL path after redirects
    final_url = getattr(response, 'geturl', lambda: requested_url)()
    path = urlparse(final_url).path
    basename = os.path.basename(path) or ''
    if basename:
        return basename
    # Last resort
    return 'downloaded_file'


def stream_download(url: str, dest_dir: Path) -> Path:
    """Download URL to dest_dir using streaming; return the full file path."""
    req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urlopen(req) as resp:
        filename = infer_filename_from_response(resp, url)
        output_path = dest_dir / filename
        with open(output_path, 'wb') as f:
            shutil.copyfileobj(resp, f)
    return output_path


def compute_sha256_with_openssl(file_path: Path) -> str:
    """Run `openssl sha256 file` and return the hex digest string."""
    try:
        result = subprocess.run(
            ['openssl', 'sha256', str(file_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        raise RuntimeError('openssl not found. Please install OpenSSL and ensure it is on PATH.') from e
    output = (result.stdout or '').strip()
    # Typical formats:
    # - "SHA256(filename)= <hash>"
    # - "SHA256(filename)=<hash>"
    # - "SHA256(file_path) = <hash>"
    # Grab the last whitespace-separated token
    parts = output.split()
    if not parts:
        raise RuntimeError(f'Unexpected openssl output: {output!r}')
    sha = parts[-1].strip()
    if not re.fullmatch(r'[0-9a-fA-F]{64}', sha):
        raise RuntimeError(f'Parsed sha256 looks invalid: {sha!r} from output {output!r}')
    return sha.lower()


def extract_version_from_filename(filename: str) -> str:
    """Extract semantic-like version from filename (e.g., 0.16.1)."""
    m = re.search(r'(\d+\.\d+(?:\.\d+)*)', filename)
    if not m:
        raise RuntimeError(f'Could not extract version from filename: {filename!r}')
    return m.group(1)


def escape_xml(text: str) -> str:
    return (
        text.replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;')
    )


def insert_release_note(appdata_path: Path, version: str, description: str, date: Optional[str] = None) -> None:
    """Insert a new release entry at the top of <releases> unless already present.

    Preserves existing indentation and avoids introducing extra blank lines.
    """
    if not appdata_path.exists():
        raise RuntimeError(f'AppData file not found: {appdata_path}')

    xml_text = appdata_path.read_text(encoding='utf-8')

    # If release for this version already exists, do nothing to avoid duplicates
    if re.search(rf'<release\s+version="{re.escape(version)}"\b', xml_text):
        print(f'Release {version} already present in {appdata_path}, skipping insertion')
        return

    date_str = date or datetime.date.today().isoformat()
    desc_xml = escape_xml(description)

    # Determine indentation
    m = re.search(r'^(?P<indent>[ \t]*)<releases>\s*$', xml_text, flags=re.MULTILINE)
    if not m:
        raise RuntimeError('Could not find <releases> tag in AppData XML')
    base_indent = m.group('indent')
    release_indent = base_indent + '  '

    entry = (
        f"{release_indent}<release version=\"{version}\" date=\"{date_str}\">\n"
        f"{release_indent}  <description>\n"
        f"{release_indent}    <p>{desc_xml}</p>\n"
        f"{release_indent}  </description>\n"
        f"{release_indent}</release>\n\n"
    )

    # Insert right after the <releases> line without consuming following whitespace
    pattern = re.compile(r'^([ \t]*<releases>\s*\n)', flags=re.MULTILINE)
    def _repl(match: re.Match) -> str:
        return match.group(0) + entry

    new_xml_text, n = pattern.subn(_repl, xml_text, count=1)
    if n == 0:
        raise RuntimeError('Could not find <releases> tag line to insert after')

    appdata_path.write_text(new_xml_text, encoding='utf-8')
    print(f'Inserted release {version} into {appdata_path}')


def run_git(commands: list[str], cwd: Path) -> str:
    result = subprocess.run(commands, cwd=str(cwd), check=True, capture_output=True, text=True)
    return (result.stdout or '') + (result.stderr or '')


def ensure_git_repo(cwd: Path) -> None:
    try:
        run_git(['git', 'rev-parse', '--is-inside-work-tree'], cwd)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f'Not a git repository: {cwd}') from e


def update_git_repo(repo_root: Path, version: str, description: str, master_branch: str = 'master', branch_prefix: str = 'release-') -> str:
    """Switch to master, pull, create/checkout release branch, and commit changes.

    Returns the branch name used.
    """
    ensure_git_repo(repo_root)

    # Fetch and update master
    print(run_git(['git', 'fetch', 'origin'], repo_root))
    print(run_git(['git', 'checkout', master_branch], repo_root))
    # Pull fast-forward only to avoid merges
    try:
        print(run_git(['git', 'pull', '--ff-only'], repo_root))
    except subprocess.CalledProcessError as e:
        raise RuntimeError('git pull --ff-only failed. Please resolve branch state manually.') from e

    branch_name = f"{branch_prefix}{version}" if branch_prefix else version

    # Checkout or create branch
    # Local exists?
    local_branch_exists = subprocess.run(['git', 'show-ref', '--verify', '--quiet', f'refs/heads/{branch_name}'], cwd=str(repo_root)).returncode == 0
    if local_branch_exists:
        print(run_git(['git', 'checkout', branch_name], repo_root))
    else:
        # Remote exists?
        remote_exists = subprocess.run(['git', 'ls-remote', '--exit-code', '--heads', 'origin', branch_name], cwd=str(repo_root)).returncode == 0
        if remote_exists:
            print(run_git(['git', 'checkout', '-b', branch_name, f'origin/{branch_name}'], repo_root))
        else:
            print(run_git(['git', 'checkout', '-b', branch_name], repo_root))

    # Stage and commit
    print(run_git(['git', 'add', '-A'], repo_root))
    commit_msg = f"update to {version} - {description}"
    # If nothing to commit, git commit exits non-zero; handle gracefully
    commit_proc = subprocess.run(['git', 'commit', '-m', commit_msg], cwd=str(repo_root), capture_output=True, text=True)
    if commit_proc.returncode != 0:
        msg = (commit_proc.stdout or '') + (commit_proc.stderr or '')
        if 'nothing to commit' in msg.lower():
            print('No changes to commit.')
        else:
            raise RuntimeError(f'git commit failed: {msg}')
    else:
        print(commit_proc.stdout)

    return branch_name


def update_yaml_text(yaml_text: str, new_dest_filename: str, new_sha256: str) -> str:
    """Update dest-filename and sha256 in the first archive source under gates module.

    This performs a structured, indentation-aware textual edit to avoid YAML dependency.
    """
    lines = yaml_text.splitlines()

    def leading_spaces(s: str) -> int:
        return len(s) - len(s.lstrip(' '))

    # Locate modules -> - name: gates block
    gates_idx = -1
    gates_indent = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*-\s*name:\s*gates\s*$", line):
            gates_idx = i
            gates_indent = leading_spaces(line)
            break
    if gates_idx == -1:
        raise RuntimeError('Could not find module with name: gates')

    # Find sources: under gates block (greater indent than gates_indent)
    sources_idx = -1
    sources_indent = None
    for i in range(gates_idx + 1, len(lines)):
        indent = leading_spaces(lines[i])
        if indent <= gates_indent and i > gates_idx:
            break  # end of gates block
        if re.match(rf"^\s{{{gates_indent + 2},}}sources:\s*$", lines[i]):
            sources_idx = i
            sources_indent = leading_spaces(lines[i])
            break
    if sources_idx == -1:
        raise RuntimeError('Could not find sources: under gates module')

    # Find first list item with type: archive under sources
    archive_item_idx = -1
    archive_item_indent = None
    for i in range(sources_idx + 1, len(lines)):
        indent = leading_spaces(lines[i])
        # End of sources block when dedenting to <= gates child level
        if indent <= sources_indent and i > sources_idx:
            break
        if re.match(rf"^\s{{{sources_indent + 2}}}-\s*type:\s*archive\b", lines[i]):
            archive_item_idx = i
            archive_item_indent = leading_spaces(lines[i])
            break
    if archive_item_idx == -1:
        raise RuntimeError('Could not find a sources list item with type: archive')

    # Within the archive mapping, locate dest-filename, url, sha256
    dest_idx = -1
    url_idx = -1
    sha_idx = -1
    url_value = None
    mapping_child_indent = archive_item_indent + 2
    for i in range(archive_item_idx + 1, len(lines)):
        indent = leading_spaces(lines[i])
        # Next list item or end of sources
        if indent <= archive_item_indent and i > archive_item_idx:
            break
        if indent != mapping_child_indent:
            continue
        if re.match(rf"^\s{{{mapping_child_indent}}}dest-filename:\s*", lines[i]):
            dest_idx = i
        elif re.match(rf"^\s{{{mapping_child_indent}}}url:\s*", lines[i]):
            url_idx = i
            # Extract URL (strip quotes if present)
            val = lines[i].split(':', 1)[1].strip()
            if len(val) >= 2 and ((val[0] == val[-1] == '"') or (val[0] == val[-1] == "'")):
                url_value = val[1:-1]
            else:
                url_value = val
        elif re.match(rf"^\s{{{mapping_child_indent}}}sha256:\s*", lines[i]):
            sha_idx = i

    if url_idx == -1 or not url_value:
        raise RuntimeError('Could not find url: inside the archive source entry')

    # Prepare replacement lines preserving indentation
    dest_prefix = ' ' * mapping_child_indent + 'dest-filename: '
    sha_prefix = ' ' * mapping_child_indent + 'sha256: '

    new_dest_line = f"{dest_prefix}{new_dest_filename}"
    new_sha_line = f"{sha_prefix}{new_sha256}"

    # Apply replacements or insertions
    if dest_idx != -1:
        lines[dest_idx] = new_dest_line
    else:
        # Insert after the archive item line
        lines.insert(archive_item_idx + 1, new_dest_line)
        # Adjust indices if needed
        if url_idx != -1 and url_idx >= archive_item_idx + 1:
            url_idx += 1
        if sha_idx != -1 and sha_idx >= archive_item_idx + 1:
            sha_idx += 1

    if sha_idx != -1:
        lines[sha_idx] = new_sha_line
    else:
        # Insert after dest-filename if present, else after archive item
        insert_pos = dest_idx if dest_idx != -1 else archive_item_idx + 1
        lines.insert(insert_pos + 1, new_sha_line)

    return "\n".join(lines) + ("\n" if yaml_text.endswith("\n") else "")


def main() -> int:
    parser = argparse.ArgumentParser(description='Update gates archive source sha256 and dest-filename from remote URL')
    parser.add_argument('--yaml-path', default=str(Path(__file__).resolve().parent / 'io.itch.nordup.TheGates.yml'), help='Path to io.itch.nordup.TheGates.yml')
    parser.add_argument('--appdata-path', default=str(Path(__file__).resolve().parent / 'io.itch.nordup.TheGates.appdata.xml'), help='Path to io.itch.nordup.TheGates.appdata.xml')
    parser.add_argument('--release-description', required=True, help='Release description text to insert into AppData XML')
    parser.add_argument('--master-branch', default='master', help='Name of the master branch to update (default: master)')
    parser.add_argument('--branch-prefix', default='release-', help='Prefix for release branch names (default: release-)')
    parser.add_argument('--no-git', action='store_true', help='Skip git operations')
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent
    yaml_path = Path(args.yaml_path).resolve()
    appdata_path = Path(args.appdata_path).resolve()

    if not yaml_path.exists():
        print(f'YAML file not found: {yaml_path}', file=sys.stderr)
        return 1

    # Read YAML text and locate URL via textual scan in case of future format changes
    yaml_text = yaml_path.read_text(encoding='utf-8')
    try:
        # We will extract the URL using the same finder we use in update function
        # Run a dry scan to get the URL
        lines = yaml_text.splitlines()
        def leading_spaces(s: str) -> int:
            return len(s) - len(s.lstrip(' '))
        gates_idx = next(i for i, ln in enumerate(lines) if re.match(r"^\s*-\s*name:\s*gates\s*$", ln))
        gates_indent = leading_spaces(lines[gates_idx])
        sources_idx = next(i for i in range(gates_idx + 1, len(lines)) if leading_spaces(lines[i]) > gates_indent and re.match(rf"^\s{{{gates_indent + 2},}}sources:\s*$", lines[i]))
        sources_indent = leading_spaces(lines[sources_idx])
        archive_item_idx = next(i for i in range(sources_idx + 1, len(lines)) if leading_spaces(lines[i]) > sources_indent and re.match(rf"^\s{{{sources_indent + 2}}}-\s*type:\s*archive\b", lines[i]))
        mapping_child_indent = leading_spaces(lines[archive_item_idx]) + 2
        url_line_idx = next(i for i in range(archive_item_idx + 1, len(lines)) if leading_spaces(lines[i]) == mapping_child_indent and re.match(rf"^\s{{{mapping_child_indent}}}url:\s*", lines[i]))
        url_raw = lines[url_line_idx].split(':', 1)[1].strip()
        if len(url_raw) >= 2 and ((url_raw[0] == url_raw[-1] == '"') or (url_raw[0] == url_raw[-1] == "'")):
            download_url = url_raw[1:-1]
        else:
            download_url = url_raw
    except StopIteration:
        print('Failed to locate the gates->sources->archive url in YAML', file=sys.stderr)
        return 1

    # Download to temp dir
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        print(f'Downloading: {download_url}')
        file_path = stream_download(download_url, tmp_dir_path)
        print(f'Downloaded to: {file_path}')

        # Compute sha256 using openssl
        sha256_hex = compute_sha256_with_openssl(file_path)
        print(f'sha256: {sha256_hex}')

        # Update YAML text
        updated_text = update_yaml_text(yaml_text, file_path.name, sha256_hex)
        yaml_path.write_text(updated_text, encoding='utf-8')
        print(f'Updated {yaml_path} with dest-filename={file_path.name} and sha256={sha256_hex}')

        # Extract version and update AppData release notes
        version = extract_version_from_filename(file_path.name)
        insert_release_note(appdata_path, version, args.release_description)

        # Delete file (TemporaryDirectory cleanup will handle it). Explicitly remove for clarity.
        try:
            file_path.unlink(missing_ok=True)
        except Exception:
            pass

    # Git operations after files changed
    if not args.no_git:
        try:
            branch = update_git_repo(repo_root, version, args.release_description, master_branch=args.master_branch, branch_prefix=args.branch_prefix)
            print(f'Git updated on branch: {branch}')
        except Exception as e:
            print(f'Git update failed: {e}', file=sys.stderr)
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
