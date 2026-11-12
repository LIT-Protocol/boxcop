#!/usr/bin/env python3
"""Scan an explicit local skill bundle without installing or running it."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server.skill_security import scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    report = scan(args.root)
    print(json.dumps(report, indent=2))
    return 2 if report['incomplete'] else 1 if report['findings'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
