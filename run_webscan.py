"""PyInstaller 入口（必须放在包外，否则 -m 相对导入在打包后会失效）。"""

import sys

from webscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
