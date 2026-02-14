# recon-progressive

A modular reconnaissance tool that combines passive and active techniques for information gathering.  
It offers an interactive menu, non‑interactive mode, parallel execution, caching, and beautiful terminal output powered by `rich`.

![demo](https://raw.githubusercontent.com/yourusername/recon-progressive/main/demo.gif)

## ✨ Features

- **Multiple modules** – WHOIS, DNS enumeration (dig), Certificate Transparency (crt.sh), Nmap port scanning.
- **Interactive & non‑interactive** – Use the menu or run from scripts with command‑line arguments.
- **Parallel execution** – Run several modules concurrently for faster results.
- **Caching** – Avoid repeated queries with configurable TTL.
- **Beautiful output** – Rich tables, panels, and colours for easy reading.
- **Report generation** – Create HTML or Markdown reports of your scans.
- **Configuration file** – Customise defaults (`~/.recon-progressive/config.toml`).

## 📦 Installation

### From PyPI (recommended)
```bash
pip install recon-progressive