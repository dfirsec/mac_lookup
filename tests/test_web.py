"""Tests for isolated network helpers."""

from typing import Any

import pytest
import requests
from mac_lookup_core import web


class FakeResponse:
    """Minimal requests response test double."""

    def __init__(self, *, status_code: int = 200, content: bytes = b"", data: Any = None) -> None:
        self.status_code = status_code
        self.content = content
        self._data = data

    def raise_for_status(self) -> None:
        """Raise for configured HTTP failures."""
        if self.status_code >= 400:
            msg = f"status {self.status_code}"
            raise requests.HTTPError(msg)

    def json(self) -> Any:
        """Return configured JSON data."""
        return self._data


class FakeSession:
    """Record requests and return a configured response."""

    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, str], int]] = []

    def get(self, url: str, *, headers: dict[str, str], timeout: int) -> FakeResponse:
        """Record one GET request."""
        self.calls.append((url, headers, timeout))
        return self.response


def test_connect_uses_timeout_and_user_agent() -> None:
    session = FakeSession(FakeResponse())

    response = web.connect("https://example.test", session_factory=lambda: session)  # type: ignore[arg-type]

    assert response.status_code == 200
    assert session.calls == [
        ("https://example.test", {"user-agent": web.USER_AGENT}, 5),
    ]


def test_connect_preserves_exception_context() -> None:
    session = FakeSession(FakeResponse(status_code=500))

    with pytest.raises(SystemExit) as exc_info:
        web.connect("https://example.test", session_factory=lambda: session)  # type: ignore[arg-type]

    assert isinstance(exc_info.value.__cause__, requests.HTTPError)


def test_get_download_link_returns_absolute_url(monkeypatch: pytest.MonkeyPatch) -> None:
    response = FakeResponse(
        content=(
            b'<a class="btn btn-primary btn-lg btn-block" href="/db.json">'
            b"Download JSON database</a>"
        )
    )
    monkeypatch.setattr(web, "connect", lambda _url: response)

    assert web.get_download_link("https://example.test/downloads") == "https://example.test/db.json"


def test_get_download_link_reports_missing_link(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web, "connect", lambda _url: FakeResponse(content=b"<html></html>"))

    assert web.get_download_link("https://example.test/downloads") == "Download link not found"


def test_maclookup_api_omits_empty_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: list[str] = []

    def fake_connect(url: str) -> FakeResponse:
        requested.append(url)
        return FakeResponse(data={"success": True})

    monkeypatch.setattr(web, "connect", fake_connect)

    assert web.maclookup_api("00:00:0C", None) == '{"success": true}'
    assert requested == ["https://api.maclookup.app/v2/macs/00:00:0C"]
