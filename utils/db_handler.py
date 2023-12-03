"""Handles database-related operations."""

import json
import sys
from pathlib import Path


def format_json_file(filepath: str) -> None:
    """Format JSON file."""
    try:
        with Path(filepath).open(encoding="utf-8") as json_file:
            content = json_file.read()

        # Parse the JSON data
        json_data = json.loads(content)

        # Format the JSON data
        formatted_lines = [json.dumps(obj, indent=4) for obj in json_data]
        formatted_json = "[\n" + ",\n".join(formatted_lines) + "\n]"

        # Overwrite the original file with the formatted JSON
        with Path(filepath).open("w") as new_file:
            new_file.write(formatted_json)

    except FileNotFoundError:
        print(f"File not found: {filepath}")
    except json.JSONDecodeError as err:
        print(f"JSON Decode Error: {err}")
    except Exception as err:
        print(f"Error: {err}")


def mac_db(filepath: str) -> list[dict[str, str]]:
    """Return mac db list."""
    try:
        with Path(filepath).open(encoding="utf-8") as json_file:
            mac_vendor = json.load(json_file)
    except json.JSONDecodeError as err:
        print("Error encountered reading mac db file.", err)
        sys.exit(1)
    else:
        return mac_vendor


def check_local_db(mac_addr: str, local_db: list) -> None | dict:
    """Check local mac db for the closest match."""
    try:
        # Normalize the MAC address (remove colons and convert to lower case)
        normalized_mac_addr = mac_addr.replace(":", "").lower()

        # Find the closest match
        closest_match = None
        max_match_length = 0
        for item in local_db:
            normalized_db_mac = item["macPrefix"].replace(":", "").lower()
            if normalized_mac_addr.startswith(normalized_db_mac) and len(normalized_db_mac) > max_match_length:
                closest_match = item
                max_match_length = len(normalized_db_mac)

    except Exception as err:
        print(f"An error occurred: {err}")
        return None
    else:
        return closest_match
