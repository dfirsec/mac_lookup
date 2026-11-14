"""Local MAC vendor database operations."""

import json
from pathlib import Path

type MacRecord = dict[str, object]


def format_json_file(filepath: str) -> None:
    """Format a JSON database file in place.

    Args:
        filepath: Path to the JSON database.
    """
    path = Path(filepath)
    try:
        json_data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return
    except json.JSONDecodeError as error:
        print(f"JSON Decode Error: {error}")
        return

    formatted_lines = [json.dumps(item, indent=4) for item in json_data]
    formatted_json = "[\n" + ",\n".join(formatted_lines) + "\n]"
    try:
        path.write_text(formatted_json, encoding="utf-8")
    except OSError as error:
        print(f"Error writing database file {filepath}: {error}")


def mac_db(filepath: str) -> list[MacRecord]:
    """Load the local MAC vendor database.

    Args:
        filepath: Path to the JSON database.

    Returns:
        Database records in their stored order.

    Raises:
        SystemExit: If the database contains invalid JSON.
    """
    try:
        with Path(filepath).open(encoding="utf-8") as json_file:
            return json.load(json_file)
    except json.JSONDecodeError as error:
        print("Error encountered reading mac db file.", error)
        raise SystemExit(1) from error


def _normalized_prefix(record: MacRecord) -> str:
    """Return a record's normalized MAC prefix.

    Args:
        record: A MAC vendor database record.

    Returns:
        The normalized MAC prefix as a lowercase string without colons.

    Raises:
        TypeError: If the macPrefix is not a string.
    """
    prefix_value = record["macPrefix"]
    if not isinstance(prefix_value, str):
        msg = "macPrefix must be a string"
        raise TypeError(msg)
    return prefix_value.replace(":", "").lower()


def check_local_db(mac_addr: str, local_db: list[MacRecord]) -> MacRecord | None:
    """Find the longest database prefix matching a MAC address.

    Args:
        mac_addr: MAC address to search for.
        local_db: Local vendor database records.

    Returns:
        The closest matching record, or ``None`` when no record matches.
    """
    normalized_mac = mac_addr.replace(":", "").lower()
    closest_match: MacRecord | None = None
    longest_prefix = 0

    try:
        for record in local_db:
            prefix = _normalized_prefix(record)
            if normalized_mac.startswith(prefix) and len(prefix) > longest_prefix:
                closest_match = record
                longest_prefix = len(prefix)
    except (KeyError, TypeError, AttributeError) as error:
        print(f"An error occurred: {error}")
        return None
    return closest_match
