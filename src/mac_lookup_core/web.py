"""Network operations for MAC Lookup."""

import json
from collections.abc import Callable
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"
MACLOOKUP_API_URL = "https://api.maclookup.app/v2/macs/"
SessionFactory = Callable[[], requests.Session]


def connect(url: str, *, session_factory: SessionFactory = requests.Session) -> requests.Response:
    """Connect to a URL and return its successful response.

    Args:
        url: URL to request.
        session_factory: Injectable requests session factory.

    Returns:
        A response with HTTP status 200.

    Raises:
        SystemExit: If the request fails or returns a status other than 200.
    """
    try:
        response = session_factory().get(url, headers={"user-agent": USER_AGENT}, timeout=5)
        response.raise_for_status()
    except requests.RequestException as error:
        raise SystemExit(error) from error
    if response.status_code != 200:
        raise SystemExit
    return response


def get_download_link(url: str) -> str:
    """Extract the JSON database download link from a downloads page.

    Args:
        url: Database downloads page URL.

    Returns:
        Absolute download URL, or the existing not-found message.
    """
    response = connect(url)
    soup = BeautifulSoup(response.content, "html.parser")
    links = soup.find_all("a", class_="btn btn-primary btn-lg btn-block")
    return next(
        (
            urljoin(url, href)
            for link in links
            if "Download JSON database" in link.text
            for href in [link.get("href")]
            if isinstance(href, str)
        ),
        "Download link not found",
    )


def maclookup_api(query: str, api_key: str | None) -> str:
    """Query maclookup.app for vendor information.

    Args:
        query: MAC address to query.
        api_key: Optional maclookup.app API key.

    Returns:
        The API JSON response serialized as a string.
    """
    url = f"{MACLOOKUP_API_URL}{query}"
    response = connect(f"{url}?apiKey={api_key}" if api_key else url)
    return json.dumps(response.json())
