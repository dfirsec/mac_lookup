"""Simple script to query for MAC address vendor info."""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from rich import print as rprint
from rich.progress import Progress, SpinnerColumn
from rich.prompt import Prompt
from rich.style import Style
from rich.text import Text
from utils.db_handler import check_loc_db, format_json_file, mac_db
from utils.mac_utils import fix_mac_addr, mac_details
from utils.web_utils import connect, maclookup_api


def read_api_key(filepath: str) -> str | None:
    """Read API key from settings file."""
    try:
        with open(filepath, encoding="utf-8") as file:
            settings = json.load(file)
            return settings["api_key"]
    except FileNotFoundError:
        print(f"Settings file not found: {filepath}")
    except KeyError:
        print(f"API key not found in settings file: {filepath}")
    except json.JSONDecodeError as err:
        print(f"JSON Decode Error: {err}")
    except Exception as err:
        print(f"Error: {err}")


# required paths
root = Path(__file__).resolve().parent
macaddress_db = str(root.joinpath("macaddress-db.json"))
settings_file = str(root.joinpath("settings.json"))

# line separator
separator = f"[bright_black]{'.' * 32}[/bright_black]"

# API Key for maclookup.app
api_key = read_api_key(settings_file)


def download_db(path: str, url: str) -> None:
    """Download mac db file."""
    resp = connect(url)

    progress = Progress("[progress.description]{task.description}", SpinnerColumn())

    with progress:
        task = progress.add_task("[+] [magenta]Downloading...[/magenta]")

        with open(path, "wb") as db_file:
            for chunk in resp.iter_content(chunk_size=1024):
                db_file.write(chunk)
                progress.refresh()

                if not progress.tasks[task].started:
                    progress.start_task(task)

    # Format the downloaded JSON file
    format_json_file(path)


def modified_date(db_file: Path) -> datetime:
    """Return last modified date of mac db file."""
    lastmod = Path(db_file).stat().st_mtime
    return datetime.strptime(time.ctime(lastmod), "%a %b %d %H:%M:%S %Y").astimezone()


def check_db() -> None:
    """Check local mac db file."""
    try:
        print(f"[+] Last updated: {modified_date(Path(macaddress_db))}")
        update_db()
    except FileNotFoundError:
        rprint("[-][red] Database file not found[/red]")
        update_db()


def update_db() -> None:
    """Update local mac db file."""
    # Online maclookup.app DB
    url = "https://maclookup.app/downloads/json-database/get-db?t=23-05-23&h=b25d6e25e9551240e67ea1b56bda672f7b36c8ee"
    message = Text("[?] Press Enter to continue, or Ctrl-C to cancel")
    message.stylize("yellow")
    try:
        Prompt.ask(message)
        rprint("[+][green] Updating database...[/green]")
        download_db(macaddress_db, url)
    except KeyboardInterrupt:
        print("\n[-] Update canceled")
        sys.exit(0)


def process_mac_addr(mac_addr: str, local_db: list) -> None:
    """Process MAC address."""
    rprint("[green][ Querying local database ][/green]")
    rprint(separator)
    mac_addr = fix_mac_addr(mac_addr)
    if match := check_loc_db(mac_addr, local_db):
        mac_details(match)
    else:
        rprint(f"[-][yellow] No results for {mac_addr}[/yellow]")
        # Check MAC prefix in local database
        mac_prefix = mac_addr.split(":")[:3]
        mac_prefix = ":".join(mac_prefix)
        prefix_match = check_loc_db(mac_prefix, local_db)
        if prefix_match:
            rprint(f"\n[+] [green]Match found for MAC Prefix {mac_prefix}[/green]")
            rprint(separator)
            mac_details(prefix_match)
        else:
            rprint(f"[yellow] No results for MAC Prefix: {mac_prefix}[/yellow]")
            rprint("\n[green][ Querying maclookup_api online database ][/green]")
            rprint(separator)
            results = json.loads(maclookup_api(mac_addr, api_key=api_key))
            if results["success"] is True:
                rprint(f"[cyan]{'MAC Addr':12}: {mac_addr}[/cyan]")
                for k, v in results.items():
                    rprint(f"{k.title().replace('_', ' '):12}: {v}")
            else:
                rprint(f"[yellow] No results for {mac_addr}[/yellow]")


def process_mac_file(mac_file: Path, local_db: list) -> None:
    """Process MAC address file."""
    if not Path(mac_file).exists():
        sys.exit(f"[red][Error][/red] {mac_file} does not exist.")

    rprint("[green][ Querying macvendors database ][/green]")
    with open(mac_file, encoding="utf8") as fileobj:
        text = [text.strip() for text in fileobj.readlines()]

    no_db_match = []
    for addr in text:
        rprint(separator)
        mac_addr = fix_mac_addr(addr)
        if match := check_loc_db(mac_addr, local_db):
            mac_details(match)
        else:
            rprint(f"[-][yellow] No results for {mac_addr}[/yellow]")
            no_db_match.append(mac_addr)

    if no_db_match:
        rprint("\n[green][ Querying macvendors online database ][/green]")
        rprint(separator)
        for mac_addr in no_db_match:
            rprint(f"\n[cyan{'MAC Addr':12}: {mac_addr}[/cyan]")
            time.sleep(1.5)
            results = json.loads(maclookup_api(mac_addr, api_key=api_key))
            if results["success"] is True:
                for k, v in results.items():
                    rprint(f"{k.title().replace('_', ' '):12}: {v}")
            else:
                rprint(f"[-] No results for {mac_addr}")


def main() -> None:
    """Run main program."""
    parser = argparse.ArgumentParser(
        prog="macLookup",
        description="Look up MAC addresses using an offline/online database.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=35),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-m", "--mac", help="MAC address to look up")
    group.add_argument("-f", "--file", help="File containing MAC addresses")
    parser.add_argument("-u", "--update", action="store_true", help="Update MAC address database")
    args = parser.parse_args()

    if args.update:
        check_db()
        sys.exit(0)  # Exit after updating db (successful)

    try:
        local_db = mac_db(macaddress_db)
    except FileNotFoundError:
        rprint("[-][red] Database file not found, downloading...[/red]")
        update_db()
        local_db = mac_db(macaddress_db)
    if args.mac:
        process_mac_addr(args.mac, local_db)
    elif args.file:
        process_mac_file(args.file, local_db)
    else:
        parser.print_help()
        sys.exit(1)  # Exit if no args provided (error)


if __name__ == "__main__":
    banner = r"""
         __  ______   ______   __                __
        /  |/  /   | / ____/  / /   ____  ____  / /____  ______
       / /|_/ / /| |/ /      / /   / __ \/ __ \/ //_/ / / / __ \
      / /  / / ___ / /___   / /___/ /_/ / /_/ / ,< / /_/ / /_/ /
     /_/  /_/_/  |_\____/  /_____/\____/\____/_/|_|\__,_/ .___/
                                                       /_/
    """

    banner_text = Text.from_markup(banner)
    banner_text.stylize(Style(color="cyan", bold=True))
    rprint(banner_text)
    main()
