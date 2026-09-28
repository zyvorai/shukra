# Social assets

| File | What it is |
|---|---|
| `shukra-social-card.html` | Source of the **light** 1600x900 card (README hero, Open Graph, X) |
| `shukra-social-card-dark.html` | Source of the **dark** 1600x900 card (README `<picture>` for dark themes only) |
| `../shukra-social.png` | Rendered light card, the README hero |
| `../shukra-social-dark.png` | Rendered dark card |
| `../../web/public/og.png` | Open Graph and X image; byte-identical copy of the **light** card (the dark card is never copied to the site) |

## Rebuild

```bash
./docs/social/build-social-card.sh
```

Needs Google Chrome and macOS `sips` (nothing to install). Override the browser with `CHROME=/path/to/chrome`.
The script renders both cards and refreshes `web/public/og.png` from the light one.

## Palette

Apple-style blue and white. Light: white to `#f5f5f7` background with a faint blue wash, ink `#1d1d1f`, secondary
`#6e6e73`, blue `#0071e3` / `#2997ff`. Dark: `#000`, text `#f5f5f7`, secondary `#a1a1a6`, blue `#2997ff`.
Orange `#ff6a2a` appears once per card, as the small dot on the first eBPF trace. Type: Helvetica Neue and Menlo.
The Zyvor "Z" mark is drawn inline in blue.

## Facts on the cards

Every claim is one the README already sources: **8 eBPF programs** (the eight `bpf/*.bpf.c` files, see
[The programs](../../README.md#the-programs)), **no guest agent**, **Apache-2.0**, and the tagline
"eBPF runtime intelligence for KVM". If the program count changes, update both HTML sources and rebuild.

## GitHub Social preview

The repository's Social preview (Settings > Social preview) cannot be set through the API. After a rebuild, upload
`docs/shukra-social.png` there by hand.
