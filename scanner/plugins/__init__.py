"""Plugin loader utilities for the scanner package.

Provides a simple `load_plugins(enabled_plugins)` function that will
import plugin modules from the `scanner.plugins` package and return
instances of classes named `Plugin`.
"""
import importlib
import pkgutil
from typing import List, Any, Optional
from scanner.logger import get_logger

LOG = get_logger("plugins")

def load_plugins(enabled_plugins: Optional[List[str]] = None) -> List[Any]:
    pkg_name = __name__  # scanner.plugins
    found_modules = []
    if enabled_plugins:
        for name in enabled_plugins:
            try:
                mod = importlib.import_module(f"{pkg_name}.{name}")
                found_modules.append(mod)
            except Exception as e:
                LOG.warning(f"Could not load plugin module '{name}': {e}")
    else:
        # autodiscover modules in this package
        package = importlib.import_module(pkg_name)
        for finder, name, ispkg in pkgutil.iter_modules(package.__path__):
            if name == "base": # Skip base.py
                continue
            try:
                mod = importlib.import_module(f"{pkg_name}.{name}")
                found_modules.append(mod)
            except Exception as e:
                LOG.warning(f"Could not load plugin module '{name}': {e}")

    instances = []
    for mod in found_modules:
        if hasattr(mod, "Plugin"):
            try:
                plugin_instance = getattr(mod, "Plugin")()
                instances.append(plugin_instance)
            except Exception as e:
                LOG.warning(f"Could not instantiate Plugin class from module {mod.__name__}: {e}")
        else:
            LOG.warning(f"Module {mod.__name__} does not contain a 'Plugin' class.")

    return instances
