#!/usr/bin/env python3
"""
recon-progressive CLI – interactive and non‑interactive modes.
Now with Rich for professional terminal output.
"""

import sys
import argparse
import json
import webbrowser
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Rich imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box
from rich.progress import track
from rich.rule import Rule

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from recon_progressive.core.loader import ModuleLoader
from recon_progressive.core.base import BaseModule
from recon_progressive.core.reporting import save_report
from recon_progressive.core.config import get_config
from recon_progressive.core.cache import get_cache, set_cache


# Load configuration
config = get_config()
OUTPUT_DIR = config.get("global", {}).get("output_dir", "recon-output")
AUTO_SAVE = config.get("global", {}).get("save_output", False)
CACHE_TTL = config.get("global", {}).get("cache_ttl", 3600)

# Rich console
console = Console()


def print_banner():
    """Display tool banner using Rich."""
    banner_text = """
╔══════════════════════════════════════════════════════════╗
║                 Recon Progressive Tool                   ║
╚══════════════════════════════════════════════════════════╝
"""
    console.print(banner_text, style="bold blue")


def print_output_panel(title, content, style="white"):
    """Print a panel with given title and content."""
    if content:
        panel = Panel(content, title=title, title_align="left", border_style=style)
        console.print(panel)


def print_parsed_intelligence(data, module_name=None):
    """Pretty‑print parsed intelligence using Rich tables with module-specific formatting."""
    console.print("\n[bold magenta]📊 PARSED INTELLIGENCE[/bold magenta]")
    
    if not isinstance(data, dict):
        console.print(data)
        return

    # Special handling for nmap open ports
    if module_name == "nmap" and "open_ports" in data and data["open_ports"]:
        table = Table(title="Open Ports", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Port", style="cyan")
        table.add_column("Protocol", style="green")
        table.add_column("State", style="yellow")
        table.add_column("Service", style="blue")
        table.add_column("Version", style="white")
        for port in data["open_ports"]:
            table.add_row(
                str(port["port"]),
                port.get("protocol", ""),
                port.get("state", ""),
                port.get("service", ""),
                port.get("version", "")
            )
        console.print(table)

    # Special handling for nmap script results
    if module_name == "nmap" and "script_results" in data and data["script_results"]:
        if isinstance(data["script_results"], dict):
            table = Table(title="Script Results", box=box.SIMPLE, header_style="bold magenta")
            table.add_column("Script", style="cyan")
            table.add_column("Output", style="white")
            for script, output in data["script_results"].items():
                if script.startswith("_"):
                    continue  # skip raw
                # Truncate long output
                out_str = str(output)
                if len(out_str) > 60:
                    out_str = out_str[:60] + "..."
                table.add_row(script, out_str)
            console.print(table)

    # Generic key-value grid for other data
    kv_table = Table(show_header=False, box=box.SIMPLE)
    kv_table.add_column("Key", style="cyan", no_wrap=True)
    kv_table.add_column("Value", style="green")
    for key, value in data.items():
        if key in ["open_ports", "script_results", "raw_output"]:
            continue
        if isinstance(value, list):
            value_str = f"[bold]{len(value)} items[/bold]"
            if value:
                preview = ", ".join(str(v)[:50] for v in value[:3])
                if len(value) > 3:
                    preview += f" … and {len(value)-3} more"
                value_str += f"\n{preview}"
        elif isinstance(value, dict):
            value_str = ", ".join(f"{k}={v}" for k, v in value.items())
        else:
            value_str = str(value)
            if "error" in value_str.lower():
                value_str = f"[red]{value_str}[/red]"
        kv_table.add_row(key, value_str)
    console.print(kv_table)

    # Summary line (quick stats)
    summary = Text()
    if "count" in data:
        summary.append(f"Total items: {data['count']} ", style="green")
    if "open_ports" in data and data["open_ports"]:
        summary.append(f"Open ports: {len(data['open_ports'])} ", style="cyan")
    if "error" in data and data["error"]:
        summary.append(f"Error: {data['error']} ", style="red")
    if summary:
        console.print(Panel(summary, border_style="blue"))


def list_profiles_for_module(loader, module_name):
    """Find module by name and print its profiles with descriptions."""
    modules_by_category = loader.get_modules_by_category()
    found_module = None
    found_name = None
    for cat in modules_by_category:
        for name, module in modules_by_category[cat].items():
            if name.lower() == module_name.lower():
                found_module = module
                found_name = name
                break
        if found_module:
            break

    if not found_module:
        console.print(f"[red]Error: Module '{module_name}' not found.[/red]")
        sys.exit(1)

    console.print(f"\n[bold cyan]Available profiles for module '{found_name}':[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
    table.add_column("Profile", style="cyan")
    table.add_column("Description")
    table.add_column("Recommendation")
    
    for pname, pinfo in found_module.profiles.items():
        table.add_row(
            pname,
            pinfo.get('desc', 'N/A'),
            pinfo.get('recommendation', 'N/A')
        )
    
    console.print(table)
    sys.exit(0)


def parallel_mode(loader, target, no_cache=False):
    """Run multiple modules/profiles concurrently."""
    console.print(f"\n[bold blue]▶ PARALLEL EXECUTION – Select modules[/bold blue]")
    console.print("(Enter module numbers one by one, then 'd' when finished)\n")

    modules_by_category = loader.get_modules_by_category()
    category_order = sorted(modules_by_category.keys())
    flat_modules = []
    idx = 1
    for cat in category_order:
        console.print(f"[{cat.upper()}]")
        for name, module in sorted(modules_by_category[cat].items()):
            flat_modules.append((cat, name, module))
            console.print(f"   {idx}. {name:<10} – {module.description}")
            idx += 1
    console.print("   d. Done selecting")
    console.print("   q. Quit")

    selected = []
    while True:
        choice = input("  Select module number (or 'd' when done): ").strip().lower()
        if choice == 'q':
            console.print("[yellow][*] Quitting.[/yellow]")
            sys.exit(0)
        if choice == 'd':
            if not selected:
                console.print("[yellow]No modules selected.[/yellow]")
                continue
            break
        try:
            mod_idx = int(choice) - 1
            if mod_idx < 0 or mod_idx >= len(flat_modules):
                raise ValueError
            cat, mod_name, module = flat_modules[mod_idx]
        except (ValueError, IndexError):
            console.print("[red]Invalid selection.[/red]")
            continue

        profile_names = list(module.profiles.keys())
        console.print(f"\nProfiles for {mod_name}:")
        for i, pname in enumerate(profile_names, 1):
            p = module.profiles[pname]
            console.print(f"   {i}. {pname} – {p['desc']}")
        prof_choice = input(f"  Select profile for {mod_name} (default: basic): ").strip()
        if prof_choice == '':
            prof_choice = 'basic'
        try:
            prof_idx = int(prof_choice) - 1
            if 0 <= prof_idx < len(profile_names):
                profile = profile_names[prof_idx]
            else:
                raise ValueError
        except ValueError:
            if prof_choice in profile_names:
                profile = prof_choice
            else:
                console.print("[red]Invalid profile, using basic.[/red]")
                profile = 'basic'

        selected.append((module, mod_name, profile))
        console.print(f"[green]Added: {mod_name} ({profile})[/green]")

    # Pre-run summary table
    console.print(f"\n[bold blue]📋 TASKS SCHEDULED[/bold blue]")
    table = Table(show_header=True, header_style="bold", box=box.ROUNDED)
    table.add_column("#", style="dim")
    table.add_column("Module", style="cyan")
    table.add_column("Profile", style="green")
    for i, (_, mod_name, profile) in enumerate(selected, 1):
        table.add_row(str(i), mod_name, profile)
    console.print(table)

    confirm = input("Proceed with parallel execution? (Y/n): ").strip().lower()
    if confirm == 'n':
        console.print("[yellow]Parallel execution cancelled.[/yellow]")
        return

    console.print(f"\n[bold blue]⚡ EXECUTING TASKS IN PARALLEL[/bold blue]\n")

    session_results = []
    failed_tasks = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=len(selected)) as executor:
        future_to_task = {}
        for module, mod_name, profile in selected:
            if not no_cache and profile not in ['custom', 'manage']:
                cached = get_cache(target, mod_name, profile, ttl=CACHE_TTL)
                if cached:
                    console.print(f"  • {mod_name} ({profile}) – [green]using cached result[/green]")
                    out = cached.get("stdout", "")
                    err = cached.get("stderr", "")
                    parsed = cached.get("parsed", {})
                    if isinstance(parsed, dict):
                        parsed["_cached"] = True
                    timestamp = cached.get("timestamp", datetime.now().isoformat())
                    session_results.append({
                        "module": mod_name,
                        "profile": profile,
                        "timestamp": timestamp,
                        "parsed": parsed,
                        "stdout": out,
                        "stderr": err
                    })
                    # Display cached result
                    if out:
                        console.print(Panel(
                            out,
                            title=f"[bold green]📦 CACHED: {mod_name} ({profile}) STDOUT[/bold green]",
                            border_style="green"
                        ))
                    if err:
                        console.print(Panel(
                            err,
                            title=f"[bold red]📦 CACHED: {mod_name} ({profile}) STDERR[/bold red]",
                            border_style="red"
                        ))
                    print_parsed_intelligence(parsed, mod_name)
                    continue

            future = executor.submit(module.run, target, profile)
            future_to_task[future] = (module, mod_name, profile)
            console.print(f"  • Started: {mod_name} ({profile})")

        for future in as_completed(future_to_task):
            module, mod_name, profile = future_to_task[future]
            task_start = time.time()
            try:
                timeout = getattr(module, 'timeouts', {}).get(profile, 30)
                out, err, retcode = future.result(timeout=timeout)
                elapsed = time.time() - task_start
                parsed = module.parse_output(out) if out else {"error": "No output"}
                timestamp = datetime.now().isoformat()

                if retcode == 0 and profile not in ['custom', 'manage']:
                    set_cache(target, mod_name, profile, out, err, parsed)

                # Display result
                if out:
                    console.print(Panel(
                        out,
                        title=f"[bold blue]🔍 {mod_name} ({profile}) STDOUT (completed in {elapsed:.1f}s)[/bold blue]",
                        border_style="blue"
                    ))
                else:
                    console.print(f"[yellow]No output produced for {mod_name} ({profile})[/yellow]")

                if err:
                    console.print(Panel(
                        err,
                        title=f"[bold red]❌ {mod_name} ({profile}) STDERR[/bold red]",
                        border_style="red"
                    ))

                print_parsed_intelligence(parsed, mod_name)

                session_results.append({
                    "module": mod_name,
                    "profile": profile,
                    "timestamp": timestamp,
                    "parsed": parsed,
                    "stdout": out,
                    "stderr": err
                })
                if retcode != 0:
                    failed_tasks.append((mod_name, profile, retcode))
            except Exception as e:
                elapsed = time.time() - task_start
                console.print(f"[red]Error in {mod_name} ({profile}) after {elapsed:.1f}s: {e}[/red]")
                failed_tasks.append((mod_name, profile, str(e)))

    total_time = time.time() - start_time
    console.print(f"\n[bold blue]📊 PARALLEL EXECUTION SUMMARY[/bold blue]")
    console.print(f"Total time: {total_time:.1f}s")
    console.print(f"Total tasks: {len(selected)}")
    if session_results:
        console.print(f"Successful: [green]{len(session_results)}[/green]")
    if failed_tasks:
        console.print(f"Failed: [red]{len(failed_tasks)}[/red]")
        for mod_name, profile, reason in failed_tasks:
            console.print(f"  • {mod_name} ({profile}): [red]{reason}[/red]")

    while True:
        console.print("\n[bold magenta]Parallel execution completed[/bold magenta]")
        console.print("  1. Run another parallel set (same target)")
        console.print("  2. Back to module selection")
        console.print("  3. Quit")
        console.print("  4. Generate report (HTML/Markdown)")
        action = input("  Select (1-4): ").strip()
        if action == '1':
            parallel_mode(loader, target, no_cache)
            return
        elif action == '2':
            return
        elif action == '3':
            console.print("[yellow][*] Quitting.[/yellow]")
            sys.exit(0)
        elif action == '4':
            if not session_results:
                console.print("[yellow]No successful scans to report.[/yellow]")
                continue
            console.print("\n--- Report Generation ---")
            fmt = input("Choose format (html/markdown) [html]: ").strip().lower()
            if fmt not in ['html', 'markdown']:
                fmt = 'html'
            try:
                report_path = save_report(target, session_results, fmt)
                console.print(f"[green]Report saved to: {report_path}[/green]")
                if fmt == 'html':
                    open_browser = input("Open in browser? (y/N): ").strip().lower()
                    if open_browser == 'y':
                        webbrowser.open(f"file://{report_path.absolute()}")
            except Exception as e:
                console.print(f"[red]Error generating report: {e}[/red]")
        else:
            console.print("[red]Invalid choice.[/red]")


def interactive_mode(loader, no_cache=False):
    """Run the interactive menu – target asked once per session."""
    while True:
        print_banner()
        target = input("▶ Target Specification\n(Enter 'q' to quit)\n  Enter target domain/IP: ").strip()
        if target.lower() == 'q':
            console.print("[yellow][*] Quitting.[/yellow]")
            sys.exit(0)
        if not target:
            continue

        session_results = []

        while True:
            modules_by_category = loader.get_modules_by_category()
            category_order = sorted(modules_by_category.keys())
            flat_modules = []
            console.print("\n[bold blue]▶ Module Selection[/bold blue]\n")
            idx = 1
            for cat in category_order:
                console.print(f"[{cat.upper()}]")
                for name, module in sorted(modules_by_category[cat].items()):
                    flat_modules.append((cat, name, module))
                    console.print(f"   {idx}. {name:<10} – {module.description}")
                    idx += 1
            console.print("  p. Run multiple modules in parallel")
            console.print("  b. Back to target entry")
            console.print("  q. Quit")

            choice = input("\n  Select module number (or 'p' for parallel): ").strip().lower()
            if choice == 'q':
                console.print("[yellow][*] Quitting.[/yellow]")
                sys.exit(0)
            if choice == 'b':
                break
            if choice == 'p':
                parallel_mode(loader, target, no_cache)
                continue

            try:
                mod_idx = int(choice) - 1
                if mod_idx < 0 or mod_idx >= len(flat_modules):
                    raise ValueError
                category, mod_name, module = flat_modules[mod_idx]
            except (ValueError, IndexError):
                console.print("[red]Invalid selection.[/red]")
                continue

            while True:
                console.print(f"\n[bold blue]▶ Profile Selection – {mod_name}[/bold blue]\n")
                profile_names = list(module.profiles.keys())
                for i, pname in enumerate(profile_names, 1):
                    p = module.profiles[pname]
                    console.print(f"   {i}. {pname} {'' if i != 1 else '(default)'}")
                    console.print(f"      ➤ {p['desc']}")
                    console.print(f"      💡 Recommended: {p['recommendation']}\n")
                console.print("  b. Back to module selection")
                console.print("  q. Quit")

                prof_choice = input("  Select profile (default: basic): ").strip().lower()
                if prof_choice == 'q':
                    console.print("[yellow][*] Quitting.[/yellow]")
                    sys.exit(0)
                if prof_choice == 'b':
                    break

                if prof_choice == '':
                    prof_choice = 'basic'
                try:
                    prof_idx = int(prof_choice) - 1
                    if 0 <= prof_idx < len(profile_names):
                        profile = profile_names[prof_idx]
                    else:
                        raise ValueError
                except ValueError:
                    if prof_choice in profile_names:
                        profile = prof_choice
                    else:
                        console.print("[red]Invalid profile selection.[/red]")
                        continue

                # Warn for long nmap scans
                if mod_name == "nmap" and profile in ["version", "full"]:
                    console.print("[yellow]⚠️ This may take a while (scanning all ports)...[/yellow]")

                # Caching check
                cached_result = None
                if not no_cache and profile not in ['custom', 'manage']:
                    cached_result = get_cache(target, mod_name, profile, ttl=CACHE_TTL)

                if cached_result:
                    out = cached_result.get("stdout", "")
                    err = cached_result.get("stderr", "")
                    parsed = cached_result.get("parsed", {})
                    if isinstance(parsed, dict):
                        parsed["_cached"] = True
                    timestamp = cached_result.get("timestamp", datetime.now().isoformat())
                    console.print(Panel("[green]Using cached result[/green]", title="📦 Cached", border_style="green"))
                else:
                    console.print(f"\n{'='*60}")
                    console.print(f"[bold]Executing {mod_name} (profile: {profile})[/bold]")
                    console.print(f"{'='*60}")
                    console.print(f"Target: {target}\n")

                    scan_start = time.time()
                    out, err, retcode = module.run(target, profile)
                    elapsed = time.time() - scan_start
                    parsed = module.parse_output(out) if out else {"error": "No output"}
                    timestamp = datetime.now().isoformat()

                    if retcode == 0 and profile not in ['custom', 'manage']:
                        set_cache(target, mod_name, profile, out, err, parsed)

                    # Show completion time
                    console.print(f"[dim]Completed in {elapsed:.1f}s[/dim]")

                # Display output
                if out:
                    console.print(Panel(
                        out,
                        title=f"[bold blue]🔍 {mod_name} ({profile}) STDOUT[/bold blue]",
                        border_style="blue"
                    ))
                else:
                    console.print("[yellow]No output produced.[/yellow]")

                if err:
                    console.print(Panel(
                        err,
                        title=f"[bold red]❌ {mod_name} ({profile}) STDERR[/bold red]",
                        border_style="red"
                    ))

                print_parsed_intelligence(parsed, mod_name)

                session_results.append({
                    "module": mod_name,
                    "profile": profile,
                    "timestamp": timestamp,
                    "parsed": parsed,
                    "stdout": out,
                    "stderr": err
                })

                # Save prompt
                if AUTO_SAVE:
                    save = 'y'
                else:
                    save = input("\n  Save output to file? (y/N): ").strip().lower()

                if save == 'y':
                    out_dir = Path(OUTPUT_DIR)
                    out_dir.mkdir(exist_ok=True)
                    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
                    safe_target = target.replace('.', '_').replace('/', '_')
                    filename = out_dir / f"{mod_name}_{safe_target}_{profile}_{timestamp_file}.json"
                    with open(filename, 'w') as f:
                        json.dump(parsed, f, indent=2)
                    console.print(f"[green]Saved to {filename}[/green]")

                # Next actions menu
                new_target = False
                while True:
                    console.print("\n[bold magenta]Next actions[/bold magenta]")
                    console.print("  1. Run again with different profile")
                    console.print("  2. Choose another module")
                    console.print("  3. New target")
                    console.print("  4. Quit")
                    console.print("  5. Generate report (HTML/Markdown)")
                    action = input("  Select (1-5): ").strip()
                    if action == '1':
                        break
                    elif action == '2':
                        break
                    elif action == '3':
                        new_target = True
                        break
                    elif action == '4':
                        console.print("[yellow][*] Quitting.[/yellow]")
                        sys.exit(0)
                    elif action == '5':
                        if not session_results:
                            console.print("[yellow]No scans performed yet.[/yellow]")
                            continue
                        console.print("\n--- Report Generation ---")
                        fmt = input("Choose format (html/markdown) [html]: ").strip().lower()
                        if fmt not in ['html', 'markdown']:
                            fmt = 'html'
                        try:
                            report_path = save_report(target, session_results, fmt)
                            console.print(f"[green]Report saved to: {report_path}[/green]")
                            if fmt == 'html':
                                open_browser = input("Open in browser? (y/N): ").strip().lower()
                                if open_browser == 'y':
                                    webbrowser.open(f"file://{report_path.absolute()}")
                        except Exception as e:
                            console.print(f"[red]Error generating report: {e}[/red]")
                        continue
                    else:
                        console.print("[red]Invalid choice.[/red]")

                if action == '2':
                    break
                if new_target:
                    break

            if new_target:
                break


def non_interactive_mode(loader, args):
    """Run a single module non‑interactively."""
    if args.list_profiles:
        list_profiles_for_module(loader, args.module)

    modules_by_category = loader.get_modules_by_category()
    found_module = None
    found_name = None
    for cat in modules_by_category:
        for name, module in modules_by_category[cat].items():
            if name.lower() == args.module.lower():
                found_module = module
                found_name = name
                break
        if found_module:
            break

    if not found_module:
        console.print(f"[red]Error: Module '{args.module}' not found.[/red]")
        sys.exit(1)

    if args.profile not in found_module.profiles:
        console.print(f"[red]Error: Profile '{args.profile}' not found in module '{found_name}'.[/red]")
        console.print(f"Available profiles: {', '.join(found_module.profiles.keys())}")
        sys.exit(1)

    # Caching check
    if not args.no_cache and args.profile not in ['custom', 'manage']:
        cached = get_cache(args.target, args.module, args.profile, ttl=CACHE_TTL)
        if cached:
            out = cached.get("stdout", "")
            err = cached.get("stderr", "")
            parsed = cached.get("parsed", {})
            if isinstance(parsed, dict):
                parsed["_cached"] = True

            if args.output_format == 'json':
                output_data = parsed
                output_str = json.dumps(output_data, indent=2)
            elif args.output_format == 'text':
                lines = []
                if out:
                    lines.append("=== STANDARD OUTPUT (cached) ===")
                    lines.append(out)
                if err:
                    lines.append("=== STANDARD ERROR (cached) ===")
                    lines.append(err)
                lines.append("=== PARSED INTELLIGENCE ===")
                for k, v in parsed.items():
                    if k == "raw_output":
                        continue
                    lines.append(f"{k}: {v}")
                output_str = "\n".join(lines)
            else:
                output_str = ""

            if args.output_file:
                with open(args.output_file, 'w') as f:
                    f.write(output_str)
            elif output_str and not args.quiet:
                print(output_str)  # plain text for non‑interactive
            sys.exit(0)

    out, err, retcode = found_module.run(args.target, args.profile)
    parsed = found_module.parse_output(out) if out else {"error": "No output"}

    if retcode == 0 and args.profile not in ['custom', 'manage']:
        set_cache(args.target, args.module, args.profile, out, err, parsed)

    if args.output_format == 'json':
        output_data = parsed
        output_str = json.dumps(output_data, indent=2)
    elif args.output_format == 'text':
        lines = []
        if out:
            lines.append("=== STANDARD OUTPUT ===")
            lines.append(out)
        if err:
            lines.append("=== STANDARD ERROR ===")
            lines.append(err)
        lines.append("=== PARSED INTELLIGENCE ===")
        for k, v in parsed.items():
            if k == "raw_output":
                continue
            lines.append(f"{k}: {v}")
        output_str = "\n".join(lines)
    else:
        output_str = ""

    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(output_str)
    elif output_str and not args.quiet:
        print(output_str)

    if retcode != 0:
        if err and args.quiet:
            print(err, file=sys.stderr)
        sys.exit(retcode)
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Recon Progressive Tool")
    parser.add_argument("--target", "-t", help="Target domain or IP")
    parser.add_argument("--module", "-m", help="Module name (e.g., nmap, crtsh)")
    parser.add_argument("--profile", "-p", help="Profile name (e.g., basic, verbose)")
    parser.add_argument("--output-format", "-f", choices=["json", "text", "none"], default="json",
                        help="Output format (default: json)")
    parser.add_argument("--output-file", "-o", help="Save output to file (instead of stdout)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banners and extra messages")
    parser.add_argument("--list-profiles", "-l", action="store_true",
                        help="List available profiles for a module (requires --module)")
    parser.add_argument("--no-cache", action="store_true", help="Ignore cached results and force fresh scans")
    args = parser.parse_args()

    loader = ModuleLoader()

    if args.list_profiles:
        if not args.module:
            parser.error("--list-profiles requires --module")
        non_interactive_mode(loader, args)
    elif args.target or args.module or args.profile:
        if not (args.target and args.module and args.profile):
            parser.error("In non‑interactive mode, --target, --module, and --profile are required.")
        non_interactive_mode(loader, args)
    else:
        interactive_mode(loader, no_cache=args.no_cache)


if __name__ == "__main__":
    main()