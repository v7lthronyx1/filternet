#!/usr/bin/env python3
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from filternet.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["probe", *sys.argv[1:]]))
