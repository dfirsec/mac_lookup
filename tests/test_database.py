"""Tests for local database operations."""

import json
from typing import TYPE_CHECKING

import pytest
from mac_lookup_core.database import check_local_db
from mac_lookup_core.database import format_json_file
from mac_lookup_core.database import mac_db

if TYPE_CHECKING:
    from pathlib import Path


def test_check_local_db_returns_longest_prefix() -> None:
    broad = {"macPrefix": "00:00", "vendorName": "Broad"}
    specific = {"macPrefix": "00:00:0C", "vendorName": "Specific"}

    assert check_local_db("00:00:0C:12:34:56", [broad, specific]) == specific


def test_check_local_db_returns_none_without_match() -> None:
    assert check_local_db("AA:BB:CC", [{"macPrefix": "00:00:0C"}]) is None


def test_check_local_db_reports_malformed_record(capsys: pytest.CaptureFixture[str]) -> None:
    assert check_local_db("00:00:0C", [{}]) is None
    assert "An error occurred" in capsys.readouterr().out


def test_format_json_file_formats_array(tmp_path: Path) -> None:
    database = tmp_path / "database.json"
    database.write_text('[{"macPrefix":"00:00:0C"}]', encoding="utf-8")

    format_json_file(str(database))

    assert json.loads(database.read_text(encoding="utf-8")) == [{"macPrefix": "00:00:0C"}]
    assert database.read_text(encoding="utf-8").startswith("[\n{")


def test_format_json_file_reports_invalid_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    database = tmp_path / "database.json"
    database.write_text("not-json", encoding="utf-8")

    format_json_file(str(database))

    assert "JSON Decode Error" in capsys.readouterr().out
    assert database.read_text(encoding="utf-8") == "not-json"


def test_mac_db_loads_records(tmp_path: Path) -> None:
    database = tmp_path / "database.json"
    database.write_text('[{"macPrefix": "00:00:0C"}]', encoding="utf-8")

    assert mac_db(str(database)) == [{"macPrefix": "00:00:0C"}]


def test_mac_db_exits_for_invalid_json(tmp_path: Path) -> None:
    database = tmp_path / "database.json"
    database.write_text("invalid", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        mac_db(str(database))

    assert exc_info.value.code == 1
    assert isinstance(exc_info.value.__cause__, json.JSONDecodeError)
