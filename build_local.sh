export app_id=$(ls *.yml | sed 's/\.[^.]*$//')
flatpak-builder --user --install --force-clean build-dir *.yml && flatpak run $app_id 