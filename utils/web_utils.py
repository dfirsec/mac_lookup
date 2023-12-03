"""Handles network operations."""

import json
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


def connect(url: str) -> requests.Response:
    """Connect to URL and return response object."""
    session = requests.Session()
    agent = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
    try:
        resp = session.get(url, headers=agent, timeout=5)
        resp.raise_for_status()
    except (
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
        requests.exceptions.ConnectionError,
        requests.exceptions.RequestException,
    ) as err:
        raise SystemExit(err) from err
    else:
        ok = 200
        if resp.status_code == ok:
            return resp
    raise SystemExit


def get_download_link(url: str) -> str:
    """Gets the json database download link."""
    response = connect(url)
    if response:
        soup = BeautifulSoup(response.content, "html.parser")
        links = soup.find_all("a", class_="btn btn-primary btn-lg btn-block")
        # Search for the download link
        return next(
            (urljoin(url, link["href"]) for link in links if "Download JSON database" in link.text),
            "Download link not found",
        )
    return "Error connecting to maclookup.app"


def maclookup_api(query: str, api_key: str | None) -> str:
    """Query maclookup.app API for vendor info."""
    maclookup_app = "https://api.maclookup.app/v2/macs/"

    try:
        resp = connect(f"{maclookup_app}{query}?apiKey={api_key}" if api_key else f"{maclookup_app}{query}")
        return json.dumps(resp.json())
    except requests.exceptions.RequestException as err:
        raise SystemExit(err) from err
