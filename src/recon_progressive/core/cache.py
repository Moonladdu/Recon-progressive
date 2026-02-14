"""
Caching module for recon-progressive.
Stores results per target, module, profile with timestamps.
"""

import json
import os
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

CACHE_DIR = Path.home() / ".recon-progressive" / "cache"

def _safe_target(target: str) -> str:
    """Convert target to safe filename."""
    # Use hash to avoid long filenames
    return hashlib.md5(target.encode()).hexdigest()

def _get_cache_path(target: str) -> Path:
    """Get cache file path for target."""
    return CACHE_DIR / f"{_safe_target(target)}.json"

def get_cache(target: str, module: str, profile: str, ttl: int = 3600) -> Optional[Dict[str, Any]]:
    """
    Retrieve cached result if exists and not expired.
    ttl in seconds (default 1 hour).
    Returns dict with keys: stdout, stderr, parsed, timestamp (iso) or None.
    """
    cache_path = _get_cache_path(target)
    if not cache_path.exists():
        return None

    try:
        with open(cache_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return None

    key = f"{module}:{profile}"
    if key not in data:
        return None

    entry = data[key]
    timestamp = datetime.fromisoformat(entry["timestamp"])
    if datetime.now() - timestamp > timedelta(seconds=ttl):
        return None  # expired

    return entry

def set_cache(target: str, module: str, profile: str, stdout: str, stderr: str, parsed: Dict[str, Any]):
    """Store result in cache."""
    cache_path = _get_cache_path(target)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing data if any
    data = {}
    if cache_path.exists():
        try:
            with open(cache_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            data = {}

    key = f"{module}:{profile}"
    data[key] = {
        "timestamp": datetime.now().isoformat(),
        "stdout": stdout,
        "stderr": stderr,
        "parsed": parsed
    }

    # Write back
    with open(cache_path, 'w') as f:
        json.dump(data, f, indent=2)

def clear_cache(target: Optional[str] = None):
    """Clear cache for a specific target or all targets."""
    if target:
        cache_path = _get_cache_path(target)
        if cache_path.exists():
            cache_path.unlink()
    else:
        # Clear all cache
        if CACHE_DIR.exists():
            import shutil
            shutil.rmtree(CACHE_DIR)
            CACHE_DIR.mkdir(parents=True)