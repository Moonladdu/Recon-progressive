# recon-progressive

A modular reconnaissance tool that combines passive and active techniques for information gathering.  
It offers an interactive menu, non‑interactive command‑line mode, parallel execution, caching, and beautiful terminal output powered by `rich`.

![demo](https://raw.githubusercontent.com/Moonladdu/Recon-progressive/main/demo.gif)  
*(Replace with actual demo GIF link)*

---

## ✨ Features

- **Multiple modules** – WHOIS, DNS enumeration (`dig`), Certificate Transparency (`crtsh`), Nmap port scanning.
- **Interactive & non‑interactive** – Use the intuitive menu or run from scripts with command‑line arguments.
- **Parallel execution** – Run several modules concurrently for faster results.
- **Caching** – Avoid repeated queries with configurable TTL; cached results are clearly marked.
- **Beautiful output** – Rich tables, panels, and colours make output easy to read.
- **Report generation** – Create HTML or Markdown reports of your scans.
- **Configuration file** – Customise defaults (`~/.recon-progressive/config.toml`).
- **Custom profiles** – Save your own Nmap argument combinations and manage them interactively.

---

## 📦 Installation

### From PyPI (recommended)

```bash
pip install recon-progressive
```

From source

```bash
git clone https://github.com/Moonladdu/Recon-progressive.git
cd Recon-progressive
pip install .
```

### External dependencies

The tool calls external binaries. Make sure they are installed:

| Tool | Purpose | Installation (Debian/Kali) | Installation (Termux) |
|------|---------|----------------------------|----------------------|
| nmap | Port scanning | sudo apt install nmap | pkg install nmap |
| curl | HTTP requests (crtsh) | sudo apt install curl | pkg install curl |
| jq | JSON processing (crtsh) | sudo apt install jq | pkg install jq |
| whois | WHOIS lookups | sudo apt install whois | pkg install whois |
| dig | DNS queries | sudo apt install dnsutils | pkg install dnsutils |

After installing these, verify they are in your PATH.

---

## 🚀 Quick Start

### Interactive mode

```bash
recon-progressive
```

1. Enter a target domain/IP (e.g., example.com).
2. Choose a module (number or p for parallel).
3. Select a profile.
4. View results and choose next actions (run again, new target, generate report, etc.).

### Non‑interactive mode (single scan)

```bash
recon-progressive --target example.com --module nmap --profile basic
```

List available profiles for a module:

```bash
recon-progressive --list-profiles --module nmap
```

Save output to a file (JSON):

```bash
recon-progressive -t example.com -m crtsh -p verbose -o crtsh.json
```

### Parallel execution

In interactive mode, type p at the module selection screen to add multiple modules/profiles and run them concurrently.

---

## 🧩 Modules & Profiles

### recon – passive intelligence

#### whois

| Profile | Description | Recommendation |
|---------|-------------|-----------------|
| basic | Standard WHOIS lookup | Default |
| verbose | Verbose WHOIS output | Full details |

#### dig

| Profile | Description | Recommendation |
|---------|-------------|-----------------|
| a | IPv4 addresses | Basic |
| aaaa | IPv6 addresses | IPv6 |
| mx | Mail servers | Email |
| ns | Name servers | DNS infra |
| txt | TXT records | Verification |
| soa | Start of Authority | Zone info |
| cname | Canonical name | Aliases |
| ptr | Reverse lookup | IP to domain |
| any | All records | Full |

#### crtsh

| Profile | Description | Recommendation |
|---------|-------------|-----------------|
| basic | Fetch unique subdomains | Default; fast |
| verbose | Full metadata + timestamps | Debugging |

### scanning – active reconnaissance

#### nmap

| Profile | Command | Description | Recommendation |
|---------|---------|-------------|-----------------|
| basic | -sS -p 22,80,443 -T4 -v | Quick SYN scan of common ports | Fast service discovery |
| stealth | -sS -p 1-1000 -T4 -v | Stealth scan of first 1000 ports | Balance speed & coverage |
| connect | -sT -p 22,80,443 -T4 -v | TCP connect scan (no root) | When root unavailable |
| version | -sS -p- -sV -T4 | Full port scan with version detection | Detailed enumeration |
| os | -sS -p 22,80,443 -O -T4 -v | OS detection | Identify target OS |
| script | -sS -p 22,80,443 -sC -T4 -v | Run default NSE scripts | Additional info |
| full | -sS -p- -sV -sC -O -T4 | Comprehensive scan (slow) | Maximum data |
| custom (interactive) | Enter custom arguments | Full flexibility | |
| manage | Manage saved custom profiles | Profile maintenance | |

---

## ⚙️ Configuration

Create `~/.recon-progressive/config.toml` to customise defaults:

```toml
[global]
output_dir = "recon-results"      # where to save files (default: recon-output)
save_output = true                 # auto-save without prompting
color = true                       # enable coloured output (default: true)
timeout = 30                       # global command timeout (seconds)
cache_ttl = 3600                    # how long to cache results (seconds, default 1 hour)

[modules.nmap]
timeout = 300                       # override for nmap (long scans)
```

---

## 📊 Output & Reporting

- **Raw output** – shown in panels with distinct colours (blue for stdout, red for stderr).
- **Parsed intelligence** – displayed as tables (e.g., open ports) or key‑value grids.
- **Cached results** – marked with 📦 and `_cached: true` in JSON.
- **Reports** – choose option 5 after a scan to generate an HTML or Markdown report containing all scans from the current target session.

---

## 🗂️ Caching

Results are stored in `~/.recon-progressive/cache/` with a TTL (default 1 hour).
Use `--no-cache` to force fresh scans. Cached results are clearly labelled.

---

## 🤝 Contributing

Contributions are welcome! Please read CONTRIBUTING.md for guidelines.

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing`).
3. Commit your changes (`git commit -m 'Add amazing feature'`).
4. Push to the branch (`git push origin feature/amazing`).
5. Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License – see the LICENSE file for details.

---

## 🙏 Acknowledgements

- Rich for stunning terminal output.
- The open‑source security community for inspiration and tools.

---

## 🧹 Cleaning Up `.bak` Files

You mentioned there are `.bak` files inside multiple directories. These should be removed before committing to keep the repository clean.

### Remove all `.bak` files recursively

```bash
find . -type f -name "*.bak" -delete
```

### Add .bak to .gitignore

Edit your .gitignore file and add a line for backup files:

```
# Backup files
*.bak
```

Then stage and commit the changes:

```bash
git add .gitignore
git commit -m "Ignore .bak files and clean up backups"
git push origin main
```

Now your repository is clean and professional. ✅
