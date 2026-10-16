# Fonts bundled with IMSIsting

Both faces ride in the binary (gresource) and are registered for the process at
startup with `FcConfigAppFontAddFile`, so the interface looks the same on a
machine that has neither installed. Nothing is written into the system font
directories and no root is involved.

| File | Family | Source | Licence |
|---|---|---|---|
| `Orbitron-Regular.ttf` | Orbitron | Google Fonts (Matt McInerney / The Orbitron Project) | SIL Open Font License 1.1 - see `Orbitron-OFL.txt` |
| `Orbitron-Bold.ttf` | Orbitron Bold | as above | as above |
| `Neuropol-Regular.otf` | Neuropol | Typodermic Fonts (Ray Larabie), taken from this machine's `/usr/local/share/fonts/n/Neuropol.otf` | Typodermic free-font terms - **not** an open licence; check before redistributing this repository |

If the Neuropol terms are a problem for distribution, delete
`Neuropol-Regular.otf` and the two `Neuropol` rules in
`native/resources/style.css` fall back to the next family in the stack.
