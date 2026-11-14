"""Command-line orchestration for MAC Lookup."""

import argparse
import json
import time
from collections.abc import Callable
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any

import yaml
from rich import print as rprint
from rich.progress import Progress
from rich.progress import SpinnerColumn
from rich.prompt import Prompt
from rich.text import Text

from mac_lookup_core.database import MacRecord
from mac_lookup_core.database import check_local_db
from mac_lookup_core.database import format_json_file
from mac_lookup_core.database import mac_db
from mac_lookup_core.mac import fix_mac_addr
from mac_lookup_core.mac import mac_details
from mac_lookup_core.web import connect
from mac_lookup_core.web import get_download_link
from mac_lookup_core.web import maclookup_api

if TYPE_CHECKING:
    from requests import Response

ROOT = Path(__file__).resolve().parents[2]
MACADDRESS_DB = str(ROOT / "macaddress-db.json")
CONFIG_FILE = str(ROOT / "config.yaml")
DOWNLOAD_PAGE = "https://maclookup.app/downloads/json-database"
SEPARATOR = f"[bright_black]{'.' * 32}[/bright_black]"

Config = dict[str, object]
ConfigReader = Callable[[], Config | None]
ApiQuery = Callable[[str, str | None], str]


class ApiResponseError(ValueError):
    """Raised when the online API returns an unusable response."""


def read_config(path: str | Path = CONFIG_FILE) -> Config | None:
    """Read optional maclookup.app configuration.

    Args:
        path: YAML configuration file path.

    Returns:
        Parsed configuration, or ``None`` if unavailable or invalid.
    """
    try:
        config = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Settings file not found: {path}")
        return None
    except (OSError, UnicodeError) as error:
        print(f"Unable to read settings file {path}: {error}")
        return None
    except yaml.YAMLError as error:
        print(f"Unable to parse settings file {path}: {error}")
        return None
    if config is None:
        return None
    if not isinstance(config, dict):
        print(f"Invalid settings file {path}: expected a YAML mapping.")
        return None
    return config


def get_api_key(config: Mapping[str, object] | None) -> str | None:
    """Extract an optional API key from parsed configuration.

    Args:
        config: Parsed settings mapping.

    Returns:
        API key text, or ``None`` when not configured.
    """
    if not config or not (api_key := config.get("maclookup_app")):
        return None
    return str(api_key)


def download_db(
    path: str,
    url: str,
    *,
    connector: Callable[[str], Response] = connect,
    formatter: Callable[[str], None] = format_json_file,
) -> None:
    """Download and format the local MAC vendor database.

    Args:
        path: Destination database path.
        url: Database download URL.
        connector: Injectable HTTP connector.
        formatter: Injectable JSON formatter.
    """
    response = connector(url)
    progress = Progress("[progress.description]{task.description}", SpinnerColumn())
    with progress:
        task = progress.add_task("[+] [magenta]Downloading...[/magenta]")
        with Path(path).open("wb") as database_file:
            for chunk in response.iter_content(chunk_size=1024):
                database_file.write(chunk)
                progress.refresh()
                if not progress.tasks[task].started:
                    progress.start_task(task)
    formatter(path)


def modified_date(db_file: Path) -> datetime:
    """Return a database file's local last-modified date.

    Args:
        db_file: Database file path.

    Returns:
        Timezone-aware modification timestamp.
    """
    return datetime.fromtimestamp(int(db_file.stat().st_mtime)).astimezone()


def check_db() -> None:
    """Display the database age and offer to update it."""
    try:
        print(f"[+] Last updated: {modified_date(Path(MACADDRESS_DB))}")
    except FileNotFoundError:
        rprint("[-][red] Database file not found[/red]")
    update_db()


def find_download_url(link_fetcher: Callable[[str], str] = get_download_link) -> str | None:
    """Resolve the database download URL and report lookup failures.

    Args:
        link_fetcher: Injectable downloads-page parser.

    Returns:
        Download URL, or ``None`` on failure.
    """
    try:
        url = link_fetcher(DOWNLOAD_PAGE)
    except SystemExit as error:
        print(f"An error occurred: {error}")
        return None
    if url == "Download link not found":
        print("Error: The download link could not be found.")
        return None
    if url.startswith("Error"):
        print(f"Error: {url}")
        return None
    return url


def update_db() -> None:
    """Prompt the user and update the local MAC vendor database."""
    if not (url := find_download_url()):
        return
    message = Text("[?] Press Enter to continue, or Ctrl-C to cancel")
    message.stylize("yellow")
    try:
        Prompt.ask(message)
        rprint("[+][green] Updating database...[/green]")
        download_db(MACADDRESS_DB, url)
    except KeyboardInterrupt:
        print("\n[-] Update canceled")
        raise SystemExit(0) from None


def parse_api_response(payload: str) -> dict[str, Any]:
    """Parse and validate a maclookup.app response.

    Args:
        payload: JSON response text.

    Returns:
        Parsed response mapping.

    Raises:
        ApiResponseError: If the response is invalid or has no success flag.
    """
    try:
        result = json.loads(payload)
    except json.JSONDecodeError as error:
        msg = "maclookup.app returned invalid JSON"
        raise ApiResponseError(msg) from error
    if not isinstance(result, dict) or "success" not in result:
        msg = "maclookup.app response is missing the 'success' field"
        raise ApiResponseError(msg)
    return result


def query_online(mac_addr: str, api_key: str | None, api_query: ApiQuery) -> dict[str, Any] | None:
    """Query the online API and turn failures into actionable output.

    Args:
        mac_addr: Normalized MAC address.
        api_key: Optional maclookup.app API key.
        api_query: Injectable API client.

    Returns:
        Parsed response, or ``None`` after a reported failure.
    """
    try:
        return parse_api_response(api_query(mac_addr, api_key))
    except (ApiResponseError, SystemExit) as error:
        rprint(f"[red]Online lookup failed for {mac_addr}: {error}[/red]")
        return None


def print_api_result(mac_addr: str, result: Mapping[str, Any], *, show_mac: bool) -> None:
    """Print one parsed API response using the existing output format.

    Args:
        mac_addr: Normalized MAC address.
        result: Parsed API response.
        show_mac: Whether to print a leading MAC address field.
    """
    if result["success"] is not True:
        message = f"[yellow] No results for {mac_addr}[/yellow]" if show_mac else f"[-] No results for {mac_addr}"
        rprint(message)
        return
    if show_mac:
        rprint(f"[cyan]{'MAC Addr':12}: {mac_addr}[/cyan]")
    for key, value in result.items():
        rprint(f"{key.title().replace('_', ' '):12}: {value}")


def process_mac_addr(
    mac_addr: str,
    local_db: list[MacRecord],
    *,
    config_reader: ConfigReader = read_config,
    api_query: ApiQuery = maclookup_api,
) -> None:
    """Look up one MAC address locally and then online if needed.

    Args:
        mac_addr: MAC address supplied by the user.
        local_db: Local vendor database records.
        config_reader: Injectable configuration reader.
        api_query: Injectable API client.
    """
    api_key = get_api_key(config_reader())
    rprint("[green][ Querying local database ][/green]")
    rprint(SEPARATOR)
    normalized_mac = fix_mac_addr(mac_addr)
    if match := check_local_db(normalized_mac, local_db):
        mac_details(match)
        return

    rprint(f"[-][yellow] No results for {normalized_mac}[/yellow]")
    rprint("\n[green][ Querying maclookup_api online database ][/green]")
    rprint(SEPARATOR)
    if result := query_online(normalized_mac, api_key, api_query):
        print_api_result(normalized_mac, result, show_mac=True)


def read_mac_file(mac_file: str | Path) -> list[str]:
    """Read stripped MAC addresses from a UTF-8 text file.

    Args:
        mac_file: Input file path.

    Returns:
        Lines stripped of surrounding whitespace.
    """
    with Path(mac_file).open(encoding="utf-8") as file_object:
        return [line.strip() for line in file_object]


def process_mac_file(
    mac_file: str | Path,
    local_db: list[MacRecord],
    *,
    config_reader: ConfigReader = read_config,
    api_query: ApiQuery = maclookup_api,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Look up all MAC addresses contained in a text file.

    Args:
        mac_file: File containing one MAC address per line.
        local_db: Local vendor database records.
        config_reader: Injectable configuration reader.
        api_query: Injectable API client.
        sleeper: Injectable delay function used for API pacing.

    Raises:
        SystemExit: If the input file does not exist.
    """
    api_key = get_api_key(config_reader())
    file_path = Path(mac_file)
    if not file_path.exists():
        msg = f"[red][Error][/red] {mac_file} does not exist."
        raise SystemExit(msg)

    rprint("[green][ Querying macvendors database ][/green]")
    unmatched: list[str] = []
    for address in read_mac_file(file_path):
        rprint(SEPARATOR)
        normalized_mac = fix_mac_addr(address)
        if match := check_local_db(normalized_mac, local_db):
            mac_details(match)
        else:
            rprint(f"[-][yellow] No results for {normalized_mac}[/yellow]")
            unmatched.append(normalized_mac)
    process_unmatched(unmatched, api_key, api_query=api_query, sleeper=sleeper)


def process_unmatched(
    unmatched: list[str],
    api_key: str | None,
    *,
    api_query: ApiQuery,
    sleeper: Callable[[float], None],
) -> None:
    """Query unmatched addresses online while respecting API pacing.

    Args:
        unmatched: Normalized addresses absent from the local database.
        api_key: Optional maclookup.app API key.
        api_query: Injectable API client.
        sleeper: Injectable delay function.
    """
    if not unmatched:
        return
    rprint("\n[green][ Querying macvendors online database ][/green]")
    rprint(SEPARATOR)
    for mac_addr in unmatched:
        rprint(f"\n[cyan]{'MAC Addr':12}: {mac_addr}[/cyan]")
        sleeper(1.5)
        if result := query_online(mac_addr, api_key, api_query):
            print_api_result(mac_addr, result, show_mac=False)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.

    Returns:
        Configured parser preserving the existing command-line interface.
    """
    parser = argparse.ArgumentParser(
        prog="macLookup",
        description="Look up MAC addresses using an offline/online database.",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=35),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-m", "--mac", help="MAC address to look up")
    group.add_argument("-f", "--file", help="File containing MAC addresses")
    parser.add_argument("-u", "--update", action="store_true", help="Update MAC address database")
    return parser


def main(argv: list[str] | None = None) -> None:
    """Run the MAC Lookup command-line program.

    Args:
        argv: Optional arguments for tests; defaults to ``sys.argv``.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.update:
        check_db()
        raise SystemExit(0)

    try:
        local_db = mac_db(MACADDRESS_DB)
    except FileNotFoundError:
        rprint("[-][red] Database file not found, downloading...[/red]")
        update_db()
        local_db = mac_db(MACADDRESS_DB)
    if args.mac:
        process_mac_addr(args.mac, local_db)
        return
    if args.file:
        process_mac_file(Path(args.file), local_db)
        return
    parser.print_help()
    raise SystemExit(1)
