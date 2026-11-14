# MAC Lookup

Look up the vendor for one MAC address or a file of addresses. The script checks a local vendor database first, then queries the maclookup.app API for addresses it cannot find locally. You can refresh the local database from the command line.

## Installation

Install Python 3.14 or newer and uv, then run:

```text
git clone https://github.com/dfirsec/mac_lookup.git
cd mac_lookup
uv sync
```

The current checkout has package references to `mac_lookup_core`, although its modules are in `utils/`. The CLI currently fails on import, and the tests may do the same until the imports and build configuration are reconciled.

## Usage

Look up one address:

```text
uv run python mac_lookup.py -m 00:00:0C
```

Look up addresses from a text file with one MAC address per line:

```text
uv run python mac_lookup.py -f mac_addresses.txt
```

Refresh the local vendor database:

```text
uv run python mac_lookup.py -u
```

The update command fetches the database and asks before writing `macaddress-db.json`. Run `uv run python mac_lookup.py --help` for all options.

## Configuration

An API key is optional. To use one for online lookups, set `maclookup_app` in `config.yaml` to your key from maclookup.app. Keep your key out of commits.

## Testing and contributing

Run the pytest suite with `uv run pytest`. See [AGENTS.md](AGENTS.md) for the repository layout and contribution guidelines. Issues and pull requests are welcome.

## License

MAC Lookup is licensed under the MIT License. See [LICENSE](LICENSE).
