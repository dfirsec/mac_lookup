# Repository Guidelines

## Project Structure & Module Organization

`mac_lookup.py` is the command-line entry point. Core behavior lives in `utils/`: `cli.py` handles arguments and lookup flow, `mac.py` formats addresses, `database.py` reads the local vendor database, and `web.py` handles HTTP requests. Corresponding pytest files are in `tests/test_*.py`. `config.yaml` holds optional API configuration; the downloaded `macaddress-db.json` is ignored by Git. There are no separate asset directories.

The current source tree uses `utils/`, while `pyproject.toml` and imports still refer to `src/mac_lookup_core`. Account for this mismatch when changing packaging or running the CLI and tests.

## Build, Test, and Development Commands

- `uv sync`: install the locked runtime and development dependencies. Python 3.14 or newer is required.
- `uv run python mac_lookup.py --help`: show the CLI options.
- `uv run python mac_lookup.py -m 00:00:0C`: look up one MAC address.
- `uv run python mac_lookup.py -f mac_addresses.txt`: look up addresses from a file.
- `uv run python mac_lookup.py -u`: download or refresh the local database; this uses the network and prompts before writing it.
- `uv run pytest`: run the test suite. Resolve the package-path mismatch above if imports fail.

## Coding Style & Naming Conventions

Use four-space indentation and follow the existing Python style: `snake_case` for modules, functions, and variables; `PascalCase` for classes; and `UPPER_CASE` for constants. Add type annotations and short docstrings to public functions. Keep CLI output and error handling consistent with nearby code. No formatter or linter is configured in `pyproject.toml`.

## Testing Guidelines

Use pytest. Place focused tests in the matching `tests/test_<module>.py` file and name cases `test_<behavior>`. Use fixtures, temporary paths, and injected callables or monkeypatching to avoid live API calls. No coverage threshold is configured. Run `uv run pytest` before submitting changes.

## Commit & Pull Request Guidelines

Recent commits use short, imperative subjects such as `Extract MAC prefix normalization helper`. Keep commits focused. In pull requests, explain the behavior changed, note relevant commands and results, and link an issue when one exists. Include CLI output examples when output changes. Do not commit API keys in `config.yaml` or the downloaded database.
