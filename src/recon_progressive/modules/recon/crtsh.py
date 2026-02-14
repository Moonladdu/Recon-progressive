"""
recon-progressive module for Certificate Transparency subdomain discovery (crt.sh).
Profiles are loaded from crtsh.yaml if available.
Includes fallback JSON parsing for basic profile when jq fails.
"""

import json
import subprocess
import yaml
from pathlib import Path
from datetime import datetime
from recon_progressive.core.base import BaseModule

class CrtshModule(BaseModule):
    """Query crt.sh for subdomains via Certificate Transparency logs."""

    def __init__(self):
        super().__init__()
        self.name = "crtsh"
        self.description = "Certificate Transparency subdomain discovery (crt.sh)"

        yaml_path = Path(__file__).parent / f"{self.name}.yaml"
        if yaml_path.exists():
            with open(yaml_path, 'r') as f:
                data = yaml.safe_load(f)
                self.profiles = data.get('profiles', {})
        else:
            self.profiles = {
                "basic": {
                    "args": [],
                    "desc": "Fetch unique subdomains from CT logs",
                    "recommendation": "Default; fast and concise"
                },
                "verbose": {
                    "args": [],
                    "desc": "Full certificate metadata + raw JSON preview",
                    "recommendation": "Debugging / manual inspection"
                }
            }

        self._current_profile = None

    def run(self, target, profile):
        self._current_profile = profile
        if profile == "basic":
            # Try pipeline; if it fails, we'll fall back in parse_output
            cmd = [
                "bash", "-c",
                f"curl -s 'https://crt.sh/?q=%.{target}&output=json' | "
                f"jq -r '.[].name_value' 2>/dev/null | sort -u"
            ]
        elif profile == "verbose":
            cmd = [
                "bash", "-c",
                f"curl -s 'https://crt.sh/?q=%.{target}&output=json'"
            ]
        else:
            return None, f"Unknown profile: {profile}", 1
        return self._run_command(cmd)

    def parse_output(self, stdout):
        profile = getattr(self, "_current_profile", "basic")

        # ----- BASIC PROFILE -----
        if profile == "basic":
            # First, try to interpret stdout as already parsed by jq (list of subdomains)
            lines = stdout.strip().splitlines()
            subdomains = [line.strip() for line in lines if line.strip()]
            if subdomains:
                return {"subdomains": subdomains, "count": len(subdomains)}

            # If no subdomains, maybe jq failed (e.g., API returned HTML). Try to parse raw JSON directly.
            try:
                data = json.loads(stdout)
                subdomains = set()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    if name_value:
                        for name in name_value.split("\n"):
                            name = name.strip()
                            if name:
                                subdomains.add(name)
                subdomains = sorted(subdomains)
                if subdomains:
                    return {
                        "subdomains": subdomains,
                        "count": len(subdomains),
                        "note": "Parsed from raw JSON (jq failed)"
                    }
                else:
                    return {"error": "No certificates found", "subdomains": [], "count": 0}
            except json.JSONDecodeError:
                # Not JSON either – probably an error page
                return {
                    "error": "No certificates found or invalid response",
                    "raw_output": stdout,
                    "subdomains": [],
                    "count": 0
                }

        # ----- VERBOSE PROFILE -----
        elif profile == "verbose":
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                return {
                    "error": "Failed to parse JSON response",
                    "raw_json": stdout,
                    "subdomains": [],
                    "count": 0
                }

            subdomains = set()
            dates = []
            for entry in data:
                name_value = entry.get("name_value", "")
                if name_value:
                    for name in name_value.split("\n"):
                        name = name.strip()
                        if name:
                            subdomains.add(name)

                not_before = entry.get("not_before")
                if not_before:
                    try:
                        dt = datetime.fromisoformat(not_before.replace('Z', '+00:00'))
                        dates.append(dt)
                    except (ValueError, TypeError):
                        pass

            result = {
                "subdomains": sorted(subdomains),
                "count": len(subdomains),
                "raw_json": stdout
            }
            if dates:
                result["first_seen"] = min(dates).isoformat()
                result["last_seen"] = max(dates).isoformat()
            if not subdomains:
                result["error"] = "No certificates found"
            return result

        else:
            return {"error": f"Parse not implemented for profile: {profile}"}