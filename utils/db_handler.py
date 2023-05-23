"""Handles database-related operations."""

import json
import sys


def format_json_file(filepath: str) -> None:
    """Format JSON file."""
    try:
        with open(filepath, encoding="utf-8") as json_file:
            content = json_file.read()

        # Parse the JSON data
        json_data = json.loads(content)

        # Format the JSON data
        formatted_lines = [json.dumps(obj, indent=4) for obj in json_data]
        formatted_json = "[\n" + ",\n".join(formatted_lines) + "\n]"

        # Overwrite the original file with the formatted JSON
        with open(filepath, "w") as new_file:
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
        with open(filepath, encoding="utf-8") as json_file:
            mac_vendor = json.load(json_file)
    except json.JSONDecodeError as err:
        print("Error encountered reading mac db file.", err)
        sys.exit(1)
    else:
        return mac_vendor


def check_loc_db(mac_addr: str, local_db: list) -> None | dict:
    """Check local mac db for match."""
    try:
        match = next(item for item in local_db if item["macPrefix"] == mac_addr)
    except StopIteration:
        return None
    else:
        return match
