from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

__all__ = []

pkg_path = Path(__file__).parent
for _, name, is_pkg in pkgutil.iter_modules([str(pkg_path)]):
    if name.startswith("__"):
        continue
    importlib.import_module(f"app.checks.{name}")
    __all__.append(name)
