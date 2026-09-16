# Companion branding

`icon.svg` is the source of the app icon (near-black rounded tile, phone outline, mint vault
dot — the same marks as the website favicon). Regenerate every platform size with:

    qlmanage -t -s 1024 -o brand brand/icon.svg && mv brand/icon.svg.png brand/icon.png
    npx tauri icon brand/icon.png

The in-app brand line uses Press Start 2P (`src/assets/fonts`, SIL OFL, licence alongside),
the same face as the phone's boot logo and the website.
