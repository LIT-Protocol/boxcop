"""Frozen or source desktop entry point. No network server or model is loaded."""
import sys

if not getattr(sys, "frozen", False):
    # Source development (`python -I -B engine_entry.py`): import this checkout's
    # server package without PYTHONPATH. Frozen bundles already contain it.
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from server.desktop import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
