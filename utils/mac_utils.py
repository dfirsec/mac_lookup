"""handle all MAC address processing."""

def fix_mac_addr(mac_addr: str) -> str:
    """Fix MAC address formatting."""
    return (
        mac_addr.replace("-", ":")
        if any(char in mac_addr for char in ["-", ":"])
        else ":".join(mac_addr[i : i + 2] for i in range(0, len(mac_addr), 2))
    )

def mac_details(match: dict) -> None:
    """Print mac details."""
    print(f"{'MAC Prefix':12}: {match['macPrefix']}")
    print(f"{'Company':12}: {match['vendorName']}")
    print(f"{'Private':12}: {match['private']}")
    print(f"{'Updated':12}: {match['lastUpdate']}")
    print(f"{'Block Type':12}: {match['blockType']}")
