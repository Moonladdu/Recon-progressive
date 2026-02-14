"""
recon-progressive module for DNS enumeration (dig).
Profiles are loaded from dig.yaml if available.
"""

import subprocess
import re
import yaml
from pathlib import Path
from recon_progressive.core.base import BaseModule

class DigModule(BaseModule):
    """DNS record enumeration using dig."""

    def __init__(self):
        super().__init__()
        self.name = "dig"
        self.description = "DNS record enumeration (A, MX, NS, TXT, ANY, etc.)"

        yaml_path = Path(__file__).parent / f"{self.name}.yaml"
        if yaml_path.exists():
            with open(yaml_path, 'r') as f:
                data = yaml.safe_load(f)
                self.profiles = data.get('profiles', {})
        else:
            # Extended profiles
            self.profiles = {
                "a": {"args": ["A"], "desc": "IPv4 addresses", "recommendation": "Basic"},
                "aaaa": {"args": ["AAAA"], "desc": "IPv6 addresses", "recommendation": "IPv6"},
                "mx": {"args": ["MX"], "desc": "Mail servers", "recommendation": "Email"},
                "ns": {"args": ["NS"], "desc": "Name servers", "recommendation": "DNS infra"},
                "txt": {"args": ["TXT"], "desc": "TXT records", "recommendation": "Verification"},
                "soa": {"args": ["SOA"], "desc": "Start of Authority", "recommendation": "Zone info"},
                "cname": {"args": ["CNAME"], "desc": "Canonical name", "recommendation": "Aliases"},
                "ptr": {"args": ["PTR"], "desc": "Reverse lookup", "recommendation": "IP to domain"},
                "any": {"args": ["ANY"], "desc": "All records", "recommendation": "Full"},
            }

    def run(self, target, profile):
        args = self.profiles[profile]["args"]
        cmd = ["dig", target] + args + ["+short"]
        return self._run_command(cmd)

    def parse_output(self, stdout):
        lines = stdout.strip().splitlines()
        # Filter out empty lines and comments
        records = [line.strip() for line in lines if line.strip() and not line.startswith(';')]
        return {"records": records, "count": len(records)}