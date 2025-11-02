"""Plugin loader utilities for the scanner package.

Provides a simple `load_plugins(enabled_plugins)` function that will
import plugin modules from the `scanner.plugins` package and return
instances of classes named `Plugin` (falling back to module objects).
"""
import importlib
import pkgutil
from typing import List, Any, Optional

def load_plugins(enabled_plugins: Optional[List[str]] = None) -> List[Any]:
    pkg_name = __name__  # scanner.plugins
    found = []
    if enabled_plugins:
        for name in enabled_plugins:
            try:
                mod = importlib.import_module(f"{pkg_name}.{name}")
                print(f"Loaded plugin: {mod}")
                found.append(mod)
            except Exception:
                continue
    else:
        # autodiscover modules in this package
        package = importlib.import_module(pkg_name)
        for finder, name, ispkg in pkgutil.iter_modules(package.__path__):
            if name == "base":
                continue
            try:
                mod = importlib.import_module(f"{pkg_name}.{name}")
                print(f"Loaded plugin: {mod}")
                found.append(mod)
            except Exception:
                continue

    instances = []
    for mod in found:
        if hasattr(mod, "Plugin"):
            try:
                instances.append(getattr(mod, "Plugin")())
            except Exception:
                instances.append(mod)
        else:
            instances.append(mod)

    return instances
