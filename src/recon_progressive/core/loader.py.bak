"""
Module loader for recon-progressive.
Recursively discovers and loads all modules from the modules/ directory.
"""

import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Dict, Any

from recon_progressive.core.base import BaseModule


class ModuleLoader:
    """Discovers and loads all modules in the modules/ directory."""

    def __init__(self):
        self.modules: Dict[str, BaseModule] = {}
        self._module_categories: Dict[str, str] = {}  # module name -> category (subdir)
        self._load_modules()

    def _load_modules(self):
        """Find all Python files in modules/ (recursive) and load any class inheriting BaseModule."""
        modules_dir = Path(__file__).parent.parent / "modules"
        if not modules_dir.exists():
            return

        for pyfile in modules_dir.rglob("*.py"):
            if pyfile.name == "__init__.py":
                continue

            # Determine category (subdirectory name relative to modules/)
            relative = pyfile.relative_to(modules_dir)
            if len(relative.parts) > 1:
                category = relative.parts[0]  # first subdirectory
            else:
                category = "uncategorized"

            # Import the module
            spec = importlib.util.spec_from_file_location(pyfile.stem, pyfile)
            if not spec or not spec.loader:
                continue
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception as e:
                print(f"Warning: Failed to load {pyfile}: {e}")
                continue

            # Find any class that inherits BaseModule (and is not BaseModule itself)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BaseModule) and obj is not BaseModule:
                    try:
                        instance = obj()
                        if hasattr(instance, 'name') and instance.name:
                            self.modules[instance.name] = instance
                            self._module_categories[instance.name] = category
                            # Also store category on the instance for easy access
                            instance._category = category
                    except Exception as e:
                        print(f"Warning: Failed to instantiate {name} from {pyfile}: {e}")

    def get_module(self, name: str) -> BaseModule:
        """Return a module by its name, or None if not found."""
        return self.modules.get(name)

    def get_modules_by_category(self) -> Dict[str, Dict[str, BaseModule]]:
        """
        Return a dictionary:
            category_name -> { module_name: module_instance, ... }
        """
        categories = {}
        for name, module in self.modules.items():
            cat = self._module_categories.get(name, "uncategorized")
            categories.setdefault(cat, {})[name] = module
        return categories

    def list_modules(self) -> Dict[str, BaseModule]:
        """Return the flat dictionary of all modules (name -> instance)."""
        return self.modules