# tests/conftest.py
import sys
if sys.version_info < (3, 12):
    raise RuntimeError("REAPER requires Python 3.12+")
