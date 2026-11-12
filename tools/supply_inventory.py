#!/usr/bin/env python3
"""Offline inventory CLI; shared with the main app's automatic collector."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server.software_inventory import Scan, main


def inventory(root: Path):
    report = Scan().run([root])
    return report['records'], report['incomplete']


if __name__ == '__main__':
    # Preserve the original explicit-root positional CLI.
    args = sys.argv[1:]
    if args and not args[0].startswith('-'): args = ['--root', args[0], *args[1:]]
    raise SystemExit(main(args))
