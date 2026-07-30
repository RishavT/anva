#!/usr/bin/env python3
"""Reproducible precommitted paired-host skill evaluation evidence gate."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from anva.skills.trusted_evals import main

if __name__ == "__main__":
    raise SystemExit(main())
