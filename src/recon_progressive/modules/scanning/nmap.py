"""
recon-progressive module for Nmap port scanning.
Includes enhanced script output parsing.
"""

import os
import json
import subprocess
import re
import shlex
import yaml
from pathlib import Path
from recon_progressive.core.base import BaseModule


class NmapModule(BaseModule):
    """Nmap port scanner with multiple profiles and custom argument input."""

    PROFILES_FILE = os.path.expanduser("~/.recon-progressive/nmap_profiles.json")

    NMAP_FLAG_HELP = {
        "-sS": {
            "desc": "SYN stealth scan (half-open)",
            "use": "Fast, less likely to be logged; default when running as root.",
            "avoid": "Requires root. May be detected by modern IDS. Not for full connect tracking."
        },
        "-sT": {
            "desc": "TCP connect scan (full handshake)",
            "use": "When you don't have root privileges. More reliable but slower.",
            "avoid": "Noisier, logged by services. Not stealthy."
        },
        "-sU": {
            "desc": "UDP scan",
            "use": "Discover UDP services (DNS, SNMP, DHCP).",
            "avoid": "Very slow; many false positives due to rate limiting."
        },
        "-sV": {
            "desc": "Service version detection",
            "use": "Identify exact service versions (e.g., Apache 2.4.7).",
            "avoid": "Adds significant time; may trigger intrusion detection."
        },
        "-O": {
            "desc": "OS fingerprinting",
            "use": "Guess target operating system.",
            "avoid": "Not always accurate; can be detected and spoofed."
        },
        "-sC": {
            "desc": "Run default NSE scripts",
            "use": "Get additional info (banners, vulnerabilities, etc.).",
            "avoid": "Some scripts are intrusive; may crash services."
        },
        "-p": {
            "desc": "Port specification (e.g., -p 22,80 or -p 1-1000 or -p-)",
            "use": "Limit scan to specific ports. -p- scans all 65535 ports.",
            "avoid": "Scanning all ports is slow; use targeted ranges for speed."
        },
        "-T0..-T5": {
            "desc": "Timing templates (T0=paranoid, T3=normal, T4=aggressive, T5=insane)",
            "use": "T4 is good for fast LAN scans; T3 for WAN.",
            "avoid": "T5 may drop packets or be detected; T0/T1 are extremely slow."
        },
        "-v": {
            "desc": "Verbose output",
            "use": "See more details during scan.",
            "avoid": "None – always useful."
        },
        "--script": {
            "desc": "Run specific NSE script(s) (e.g., --script vuln, --script http-title)",
            "use": "Targeted tests (vulnerability scanning, enumeration).",
            "avoid": "Some scripts are invasive; read descriptions before running."
        },
        "-Pn": {
            "desc": "Skip host discovery (treat all hosts as up)",
            "use": "When firewall blocks ping probes; scan IPs that might be down.",
            "avoid": "Wastes time on dead hosts if you know they're up."
        },
        "-A": {
            "desc": "Aggressive scan (OS, version, script, traceroute)",
            "use": "Quick overview with maximum info.",
            "avoid": "Very noisy; combines -O, -sV, -sC, --traceroute."
        }
    }

    def __init__(self):
        super().__init__()
        self.name = "nmap"
        self.description = "Nmap port scanner (active reconnaissance)"

        yaml_path = Path(__file__).parent / f"{self.name}.yaml"
        if yaml_path.exists():
            with open(yaml_path, 'r') as f:
                data = yaml.safe_load(f)
                self.builtin_profiles = data.get('profiles', {})
        else:
            self.builtin_profiles = {
                "basic": {
                    "args": ["-sS", "-p", "22,80,443", "-T4", "-v"],
                    "desc": "Quick SYN scan of common ports",
                    "recommendation": "Fast service discovery"
                },
                "stealth": {
                    "args": ["-sS", "-p", "1-1000", "-T4", "-v"],
                    "desc": "Stealth scan of first 1000 ports",
                    "recommendation": "Balance speed and coverage"
                },
                "connect": {
                    "args": ["-sT", "-p", "22,80,443", "-T4", "-v"],
                    "desc": "TCP connect scan (no root needed)",
                    "recommendation": "When root unavailable"
                },
                "version": {
                    "args": ["-sS", "-p-", "-sV", "-T4"],
                    "desc": "Full port scan with version detection",
                    "recommendation": "Detailed service enumeration"
                },
                "os": {
                    "args": ["-sS", "-p", "22,80,443", "-O", "-T4", "-v"],
                    "desc": "Add OS detection to basic scan",
                    "recommendation": "Identify target OS"
                },
                "script": {
                    "args": ["-sS", "-p", "22,80,443", "-sC", "-T4", "-v"],
                    "desc": "Run default NSE scripts",
                    "recommendation": "Additional info (banners, vulns)"
                },
                "full": {
                    "args": ["-sS", "-p-", "-sV", "-sC", "-O", "-T4"],
                    "desc": "Comprehensive scan (all ports, versions, scripts, OS)",
                    "recommendation": "Maximum data (slow)"
                },
                "custom": {
                    "args": [],
                    "desc": "Enter custom Nmap arguments interactively (type 'help' for options)",
                    "recommendation": "Full flexibility"
                },
                "manage": {
                    "args": ["manage"],
                    "desc": "Manage custom profiles (delete, modify)",
                    "recommendation": "Profile maintenance"
                }
            }

        self.user_profiles = self._load_user_profiles()
        self.profiles = {**self.builtin_profiles, **self.user_profiles}

        self.timeouts = {
            "basic": 30,
            "stealth": 30,
            "connect": 30,
            "version": 120,
            "os": 30,
            "script": 30,
            "full": 180,
            "custom": 300,
            "manage": 5
        }
        for name in self.user_profiles:
            self.timeouts[name] = 300

    def _load_user_profiles(self):
        if not os.path.exists(self.PROFILES_FILE):
            return {}
        try:
            with open(self.PROFILES_FILE, 'r') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return {}
            profiles = {}
            for name, info in data.items():
                if isinstance(info, dict) and "args" in info:
                    profiles[name] = {
                        "args": info["args"],
                        "desc": info.get("desc", f"User‑defined profile: {' '.join(info['args'])}"),
                        "recommendation": info.get("recommendation", "Custom profile")
                    }
            return profiles
        except (json.JSONDecodeError, IOError):
            return {}

    def _save_user_profiles(self):
        os.makedirs(os.path.dirname(self.PROFILES_FILE), exist_ok=True)
        try:
            with open(self.PROFILES_FILE, 'w') as f:
                json.dump(self.user_profiles, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save profiles: {e}")

    def _show_nmap_help(self, flag=None):
        if flag:
            flag = flag.strip()
            if flag in self.NMAP_FLAG_HELP:
                info = self.NMAP_FLAG_HELP[flag]
                print(f"\n{flag}")
                print(f"  Description: {info['desc']}")
                print(f"  When to use: {info['use']}")
                print(f"  When NOT to use: {info['avoid']}")
            else:
                print(f"No detailed help for '{flag}'. Try 'help' for list of common flags.")
        else:
            print("\nCommon Nmap flags (type 'help <flag>' for details):")
            print(f"{'Flag':<10} {'Description':<40} {'Use Case':<30}")
            print("-" * 80)
            for flag, info in self.NMAP_FLAG_HELP.items():
                desc_short = info['desc'][:38] + "..." if len(info['desc']) > 40 else info['desc']
                use_short = info['use'][:28] + "..." if len(info['use']) > 30 else info['use']
                print(f"{flag:<10} {desc_short:<40} {use_short:<30}")
            print("\nExamples:")
            print("  -p 22,80 -sV                # Version scan on ports 22,80")
            print("  -p- -sS -T4                 # Full SYN scan")
            print("  -p 1-1000 -sC -O            # Script + OS on first 1000 ports")
            print("  --script vuln -p 80,443      # Vulnerability scripts on web ports")

    def _manage_profiles(self):
        while True:
            if not self.user_profiles:
                print("\nNo custom profiles found.")
                return

            print("\n--- Manage Custom Profiles ---")
            names = list(self.user_profiles.keys())
            for i, name in enumerate(names, 1):
                args_str = " ".join(self.user_profiles[name]["args"])
                print(f"{i}. {name}: {args_str}")
            print("d. Delete a profile")
            print("m. Modify a profile")
            print("x. Exit management")
            choice = input("Select option: ").strip().lower()

            if choice == 'x':
                return
            elif choice == 'd':
                try:
                    num = int(input("Enter profile number to delete: ").strip())
                    if 1 <= num <= len(names):
                        name = names[num-1]
                        del self.user_profiles[name]
                        self._save_user_profiles()
                        self.profiles = {**self.builtin_profiles, **self.user_profiles}
                        print(f"Profile '{name}' deleted.")
                    else:
                        print("Invalid number.")
                except ValueError:
                    print("Invalid input.")
            elif choice == 'm':
                try:
                    num = int(input("Enter profile number to modify: ").strip())
                    if 1 <= num <= len(names):
                        name = names[num-1]
                        current_args = self.user_profiles[name]["args"]
                        print(f"Current arguments: {' '.join(current_args)}")
                        print("Enter new arguments (or leave empty to keep current).")
                        print("Type 'help' for flag assistance.")
                        while True:
                            new_input = input(">>> ").strip()
                            if not new_input:
                                new_args = current_args
                                break
                            if new_input.lower().startswith("help"):
                                parts = new_input.split(maxsplit=1)
                                if len(parts) == 1:
                                    self._show_nmap_help()
                                else:
                                    self._show_nmap_help(parts[1])
                                continue
                            try:
                                new_args = shlex.split(new_input)
                                break
                            except Exception as e:
                                print(f"Error parsing arguments: {e}. Try again.")
                        new_name = input(f"New profile name (leave empty to keep '{name}'): ").strip()
                        if not new_name:
                            new_name = name
                        if new_name != name:
                            del self.user_profiles[name]
                        self.user_profiles[new_name] = {
                            "args": new_args,
                            "desc": f"User‑defined: {' '.join(new_args)}",
                            "recommendation": "Custom profile"
                        }
                        self._save_user_profiles()
                        self.profiles = {**self.builtin_profiles, **self.user_profiles}
                        print(f"Profile '{name}' updated as '{new_name}'.")
                    else:
                        print("Invalid number.")
                except ValueError:
                    print("Invalid input.")
            else:
                print("Invalid option.")

    def run(self, target, profile):
        if profile not in self.profiles:
            return None, f"Unknown profile: {profile}", 1

        if profile == "manage":
            self._manage_profiles()
            return "Profile management completed.", "", 0

        if profile == "custom":
            print("\n[?] Enter custom Nmap arguments (e.g., -p 22,80 -sV -O)")
            print("    Type 'help' for list of common flags with use cases.")
            print("    Type 'help <flag>' for detailed info (e.g., 'help -sS').")
            print("    Leave empty to cancel.\n")
            while True:
                user_input = input(">>> ").strip()
                if not user_input:
                    return "", "Custom scan cancelled by user.", 1
                if user_input.lower().startswith("help"):
                    parts = user_input.split(maxsplit=1)
                    if len(parts) == 1:
                        self._show_nmap_help()
                    else:
                        self._show_nmap_help(parts[1])
                    continue
                try:
                    args = shlex.split(user_input)
                    break
                except Exception as e:
                    print(f"Error parsing arguments: {e}. Try again.")
        else:
            args = self.profiles[profile]["args"]

        cmd = ["nmap"] + args + [target]
        timeout = self.timeouts.get(profile, 30)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            stdout, stderr, rc = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout} seconds", 124
        except FileNotFoundError:
            return "", "nmap binary not found. Install nmap first.", 1

        if profile == "custom" and rc == 0:
            print("\n--- Scan completed ---")
            save = input("Save these arguments as a new profile? (y/N): ").strip().lower()
            if save == 'y':
                name = input("Enter a name for the new profile: ").strip()
                if name:
                    if name in self.builtin_profiles:
                        print(f"Profile name '{name}' conflicts with a built‑in profile. Not saved.")
                    else:
                        desc = f"User‑defined: {' '.join(args)}"
                        self.user_profiles[name] = {
                            "args": args,
                            "desc": desc,
                            "recommendation": "Custom profile"
                        }
                        self.profiles[name] = self.user_profiles[name]
                        self.timeouts[name] = 300
                        self._save_user_profiles()
                        print(f"Profile '{name}' saved. It will appear in future selections.")
                else:
                    print("Profile not saved (empty name).")

        return stdout, stderr, rc

    def parse_output(self, stdout):
        """Extract open ports, OS guess, and enhanced script results."""
        if not stdout:
            return {"error": "No output produced."}

        result = {
            "open_ports": [],
            "os_guess": None,
            "script_results": {},
            "raw_output": stdout
        }

        port_re = re.compile(
            r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$',
            re.MULTILINE
        )
        os_re = re.compile(r'Aggressive OS guesses:\s*(.+)')

        lines = stdout.splitlines()
        in_script_section = False
        current_script = None
        script_buffer = []

        for line in lines:
            m = port_re.match(line)
            if m:
                port, proto, state, service, version = m.groups()
                version = version.strip() if version else ""
                result["open_ports"].append({
                    "port": int(port),
                    "protocol": proto,
                    "state": state,
                    "service": service,
                    "version": version
                })
                continue

            m = os_re.search(line)
            if m:
                result["os_guess"] = m.group(1).strip()
                continue

            # Enhanced script parsing
            script_match = re.match(r'\|_?([a-z0-9-]+):\s*(.+)', line, re.IGNORECASE)
            if script_match:
                script_name = script_match.group(1).strip()
                script_value = script_match.group(2).strip()
                result["script_results"][script_name] = script_value
                continue

            # Multi-line script output (crude: collect all lines between script lines)
            if "NSE:" in line or "Script:" in line:
                in_script_section = True
                script_buffer = [line]
                continue
            if in_script_section:
                if not line.strip():
                    in_script_section = False
                    if script_buffer:
                        result["script_results"]["_raw_script"] = "\n".join(script_buffer)
                else:
                    script_buffer.append(line)

        # If we have raw script lines but no structured keys, store as list
        if script_buffer and not result["script_results"]:
            result["script_results"]["_raw"] = "\n".join(script_buffer)

        if not result["open_ports"] and not result["os_guess"] and not result["script_results"]:
            result["warning"] = "No structured data could be parsed. Raw output provided."

        return result