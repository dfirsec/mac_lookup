"""Tests for MAC address helpers."""

import pytest
from mac_lookup_core.mac import fix_mac_addr
from mac_lookup_core.mac import mac_details


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("00000C", "00:00:0C"),
        ("00-00-0C", "00:00:0C"),
        ("00:00:0C", "00:00:0C"),
        ("ABC", "AB:C"),
        ("", ""),
    ],
)
def test_fix_mac_addr_preserves_existing_formatting_behavior(value: str, expected: str) -> None:
    assert fix_mac_addr(value) == expected


def test_mac_details_prints_all_fields(capsys: pytest.CaptureFixture[str]) -> None:
    mac_details(
        {
            "macPrefix": "00:00:0C",
            "vendorName": "Cisco",
            "private": False,
            "lastUpdate": "2024-01-01",
            "blockType": "MA-L",
        }
    )

    output = capsys.readouterr().out
    assert "MAC Prefix  : 00:00:0C" in output
    assert "Company     : Cisco" in output
    assert "Block Type  : MA-L" in output
