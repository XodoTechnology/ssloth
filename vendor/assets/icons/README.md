# Vendor marks

One 8-bit greyscale PNG per vendor (`families::Vendor`), used by
`icons::mask_texture`. They are
**masks, not artwork**: luminance is uploaded as alpha with the RGB left white,
and the GUI multiplies in `Vendor::tint()`. That keeps them legible on the dark
list background, lets one image serve every state, and sidesteps the fact that
`image::decode` returns no alpha channel.

They are shipped trimmed rather than padded to a square — the Supermicro and AMI
logos are much wider than they are tall, and letterboxing them into a square
throws away the width they need to stay readable at 20 px.

| file | family | source |
|---|---|---|
| `aten.png` | Supermicro / ATEN | Wikimedia Commons, `Super Micro Computer Logo.svg` |
| `ami.png` | Quanta / AMI MegaRAC | Wikimedia Commons, `American Megatrends logo.svg`, cropped to the leading pyramid |
| `ilo.png` | HP iLO 4 | simple-icons, `hp.svg` |
| `idrac.png` | Dell iDRAC 9 | simple-icons, `dell.svg` |
| `asrock.png` | ASRock Rack / AMI SP-X | ASRock wordmark |
| `gigabyte.png` | Gigabyte / Avocent MergePoint | Wikimedia Commons, `Gigabyte Technology Logo.svg` |
| `asus.png` | ASUS (AMI SP-X) | simple-icons 16.33.0, `asus.svg` |
| `lenovo.png` | Lenovo (AMI SP-X) | simple-icons 16.33.0, `lenovo.svg` |
| `intel.png` | Intel (AMI SP-X) | simple-icons 16.33.0, `intel.svg` |

Tyan, Quanta and Inspur have no mark in simple-icons; they show AMI's, since
what those boards run is AMI's firmware, with their own name beside it.

Regenerating one, given the vendor SVG:

```sh
rsvg-convert -h 400 vendor.svg -o raw.png
magick raw.png -background white -flatten -alpha off -colorspace Gray -negate \
  -auto-level -trim +repage -resize 128x128 -depth 8 \
  -define png:color-type=0 -strip out.png
```

`-alpha off` matters: without it `-negate` inverts the alpha channel too and the
result is an empty image. Flattening onto *white* and negating (rather than
`-alpha extract`) keeps logos whose mark is an outline — the Supermicro ellipse
would otherwise fill in solid.

The logos are the vendors' trademarks, used here only to identify their own
hardware.
