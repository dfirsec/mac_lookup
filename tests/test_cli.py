"""Tests for command-line orchestration and boundary behavior."""


from typing import TYPE_CHECKING

import pytest
from mac_lookup_core import cli

if TYPE_CHECKING:
    from pathlib import Path


def test_read_config_reads_api_key(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("maclookup_app: secret", encoding="utf-8")

    assert cli.read_config(config) == {"maclookup_app": "secret"}


def test_read_config_reports_invalid_mapping(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("- invalid", encoding="utf-8")

    assert cli.read_config(config) is None
    assert "expected a YAML mapping" in capsys.readouterr().out


def test_get_api_key_handles_optional_config() -> None:
    assert cli.get_api_key(None) is None
    assert cli.get_api_key({"maclookup_app": None}) is None
    assert cli.get_api_key({"maclookup_app": 123}) == "123"


def test_parse_api_response_rejects_invalid_json() -> None:
    with pytest.raises(cli.ApiResponseError, match="invalid JSON") as exc_info:
        cli.parse_api_response("not-json")

    assert exc_info.value.__cause__ is not None


def test_parse_api_response_requires_success_flag() -> None:
    with pytest.raises(cli.ApiResponseError, match="success"):
        cli.parse_api_response("{}")


def test_find_download_url_stops_when_link_is_missing(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.find_download_url(lambda _url: "Download link not found") is None
    assert "could not be found" in capsys.readouterr().out


def test_process_mac_addr_uses_local_match_without_network(capsys: pytest.CaptureFixture[str]) -> None:
    records = [
        {
            "macPrefix": "00:00:0C",
            "vendorName": "Cisco",
            "private": False,
            "lastUpdate": "2024-01-01",
            "blockType": "MA-L",
        }
    ]

    def unexpected_query(_mac: str, _key: str | None) -> str:
        msg = "online API should not be called"
        raise AssertionError(msg)

    cli.process_mac_addr(
        "00000C123456",
        records,
        config_reader=lambda: None,
        api_query=unexpected_query,
    )

    assert "Cisco" in capsys.readouterr().out


def test_process_mac_addr_handles_invalid_online_response(capsys: pytest.CaptureFixture[str]) -> None:
    cli.process_mac_addr(
        "AABBCC",
        [],
        config_reader=lambda: None,
        api_query=lambda _mac, _key: "invalid",
    )

    assert "Online lookup failed for AA:BB:CC" in capsys.readouterr().out


def test_process_mac_file_rejects_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.txt"

    with pytest.raises(SystemExit, match="does not exist"):
        cli.process_mac_file(missing, [], config_reader=lambda: None)


def test_process_mac_file_injects_api_and_sleep(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mac_file = tmp_path / "macs.txt"
    mac_file.write_text("AABBCC\n", encoding="utf-8")
    sleeps: list[float] = []
    queries: list[tuple[str, str | None]] = []

    def query(mac: str, api_key: str | None) -> str:
        queries.append((mac, api_key))
        return '{"success": true, "vendor": "Example"}'

    cli.process_mac_file(
        mac_file,
        [],
        config_reader=lambda: {"maclookup_app": "key"},
        api_query=query,
        sleeper=sleeps.append,
    )

    output = capsys.readouterr().out
    assert "MAC Addr    : AA:BB:CC" in output
    assert "Vendor      : Example" in output
    assert queries == [("AA:BB:CC", "key")]
    assert sleeps == [1.5]


def test_build_parser_keeps_mac_and_file_mutually_exclusive() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.build_parser().parse_args(["--mac", "AABBCC", "--file", "macs.txt"])

    assert exc_info.value.code == 2
