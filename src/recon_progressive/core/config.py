"""
Configuration management for recon-progressive.
Loads settings from ~/.recon-progressive/config.toml.
"""

import os
import tomllib
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG = {
    "global": {
        "timeout": 30,
        "output_dir": "recon-output",
        "save_output": False,
        "color": True,
        "cache_ttl": 3600,   # default 1 hour
    },
    "modules": {
        # Module-specific overrides
    },
    "favorites": {
        # Favorite modules/profiles per target type? Could be added later.
    }
}

CONFIG_PATH = Path.home() / ".recon-progressive" / "config.toml"

def load_config() -> Dict[str, Any]:
    """Load config from file, return merged with defaults."""
    config = DEFAULT_CONFIG.copy()
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "rb") as f:
                user_config = tomllib.load(f)
            # Deep merge (simple top-level merge for now)
            for section, values in user_config.items():
                if section in config:
                    config[section].update(values)
                else:
                    config[section] = values
        except (tomllib.TOMLDecodeError, IOError) as e:
            print(f"Warning: Could not parse config file: {e}")
    return config

def get_config() -> Dict[str, Any]:
    """Singleton pattern – load once and cache."""
    if not hasattr(get_config, "_cache"):
        get_config._cache = load_config()
    return get_config._cache