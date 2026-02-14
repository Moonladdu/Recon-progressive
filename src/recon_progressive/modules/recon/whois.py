"""
recon-progressive module for WHOIS lookup.
Profiles are loaded from whois.yaml if available.
"""

import subprocess
import re
import yaml
from pathlib import Path
from recon_progressive.core.base import BaseModule

class WhoisModule(BaseModule):
    """WHOIS lookup module with enhanced parsing."""

    def __init__(self):
        super().__init__()
        self.name = "whois"
        self.description = "Domain WHOIS lookup (registrar, dates, nameservers)"

        # Load profiles from YAML
        yaml_path = Path(__file__).parent / f"{self.name}.yaml"
        if yaml_path.exists():
            with open(yaml_path, 'r') as f:
                data = yaml.safe_load(f)
                self.profiles = data.get('profiles', {})
        else:
            # Fallback hardcoded profiles
            self.profiles = {
                "basic": {
                    "args": [],
                    "desc": "Standard WHOIS lookup",
                    "recommendation": "Default"
                },
                "verbose": {
                    "args": [],
                    "desc": "Verbose WHOIS output",
                    "recommendation": "Full details"
                }
            }

    def run(self, target, profile):
        cmd = ["whois", target]
        return self._run_command(cmd)

    def parse_output(self, stdout):
        """Extract structured fields from WHOIS output."""
        lines = stdout.splitlines()
        parsed = {
            "raw": stdout,
            "registrar": None,
            "creation_date": None,
            "expiry_date": None,
            "updated_date": None,
            "name_servers": [],
            "registrant": None,
            "admin": None,
            "tech": None,
        }

        # Common patterns (case-insensitive)
        patterns = {
            "registrar": [
                r"Registrar:\s*(.+)",
                r"Sponsoring Registrar:\s*(.+)",
            ],
            "creation_date": [
                r"Creation Date:\s*(.+)",
                r"Created on:\s*(.+)",
                r"Registered on:\s*(.+)",
            ],
            "expiry_date": [
                r"Registry Expiry Date:\s*(.+)",
                r"Expires on:\s*(.+)",
                r"Expiration Date:\s*(.+)",
            ],
            "updated_date": [
                r"Updated Date:\s*(.+)",
                r"Last Updated on:\s*(.+)",
            ],
            "name_servers": [
                r"Name Server:\s*(.+)",
                r"Nameserver:\s*(.+)",
            ],
            "registrant": [
                r"Registrant:\s*(.+)",
                r"Registrant Name:\s*(.+)",
            ],
            "admin": [
                r"Administrative Contact:\s*(.+)",
                r"Admin Email:\s*(.+)",
            ],
            "tech": [
                r"Technical Contact:\s*(.+)",
                r"Tech Email:\s*(.+)",
            ],
        }

        for key, regex_list in patterns.items():
            for pattern in regex_list:
                matches = re.findall(pattern, stdout, re.IGNORECASE)
                if matches:
                    if key == "name_servers":
                        # Collect all unique name servers
                        parsed[key] = list(set(matches))
                    else:
                        # Take first match
                        parsed[key] = matches[0].strip()
                    break  # stop after first pattern match

        # Remove raw if too long? Keep it.
        return parsed