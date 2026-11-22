#!/usr/bin/env python3
"""QuickSentry - Windows GUI entry point.

Build to .exe:  build_exe.bat   (or see README)
Run from source: python quicksentry_gui.py          (asks for admin)
Preview the UI:  python quicksentry_gui.py --demo   (any OS, touches nothing)
"""

import sys

from quicksentry.app import main

if __name__ == "__main__":
    sys.exit(main())
