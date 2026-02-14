#!/usr/bin/env python3
"""
Base module class for all reconnaissance modules.
All modules must inherit from BaseModule and implement required methods.
"""

import subprocess
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional

class BaseModule(ABC):
    """Abstract base class for all recon modules."""

    def __init__(self):
        self.name = self.__class__.__name__.lower()
        self.description = ""
        # profile -> { "args": list, "desc": str, "recommendation": str }
        self.profiles = {}

    @abstractmethod
    def run(self, target: str, profile: str = "basic") -> Tuple[str, str, int]:
        """
        Execute the module with subprocess.
        Returns (stdout, stderr, returncode).
        """
        pass

    @abstractmethod
    def parse_output(self, stdout: str) -> Dict:
        """
        Parse raw command output into structured data.
        Returns a dictionary with extracted intelligence.
        """
        pass

    def get_profiles(self) -> List[str]:
        """Return list of available profile names."""
        return list(self.profiles.keys())

    def get_profile_info(self, profile: str) -> Dict:
        """Return metadata for a given profile (args, description, recommendation)."""
        return self.profiles.get(profile, {"args": [], "desc": "", "recommendation": ""})

    def _run_command(self, cmd: List[str]) -> Tuple[str, str, int]:
        """Helper to run a command and return output."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            return result.stdout, result.stderr, result.returncode
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", 127
        except subprocess.TimeoutExpired:
            return "", "Command timed out after 30 seconds", 124