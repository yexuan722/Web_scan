"""生成图标资源（PNG + ICO）。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from webscan.tray import make_icon_image  # noqa: E402


def main() -> None:
    out = ROOT / "assets"
    out.mkdir(exist_ok=True)

    big = make_icon_image(256)
    png = out / "icon.png"
    big.save(png, format="PNG")

    ico = out / "webscan.ico"
    big.save(ico, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])

    print(f"OK {png} ({png.stat().st_size} bytes)")
    print(f"OK {ico} ({ico.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
