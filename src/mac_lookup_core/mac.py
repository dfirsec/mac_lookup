"""MAC address formatting and display helpers."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mac_lookup_core.database import MacRecord


def fix_mac_addr(mac_addr: str) -> str:
    """Convert a plain or hyphenated MAC address to colon-separated form.

    Args:
        mac_addr: MAC address in its original representation.

    Returns:
        The address with hyphens replaced or pairs separated by colons.
    """
    if "-" in mac_addr or ":" in mac_addr:
        return mac_addr.replace("-", ":")
    return ":".join(mac_addr[index : index + 2] for index in range(0, len(mac_addr), 2))


def mac_details(match: MacRecord) -> None:
    """Print the fields of a MAC vendor database match.

    Args:
        match: Database record to display.
    """
    print(f"{'MAC Prefix':12}: {match['macPrefix']}")
    print(f"{'Company':12}: {match['vendorName']}")
    print(f"{'Private':12}: {match['private']}")
    print(f"{'Updated':12}: {match['lastUpdate']}")
    print(f"{'Block Type':12}: {match['blockType']}")
