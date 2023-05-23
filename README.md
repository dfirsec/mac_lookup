# MAC Lookup

Simple script to query for MAC address vendor info.

## Description

MAC Lookup is a Python script that allows you to query and retrieve information about MAC addresses. It provides functionality to query a local MAC address database as well as an online database using the maclookup.app API. The script supports querying a single MAC address or processing a file containing multiple MAC addresses.

## Features

- Query MAC address vendor information using an offline/online database.
- Update the local MAC address database.
- Query a single MAC address or process a file with multiple MAC addresses.

## Requirements

- Python 3.x

## Installation

1. Clone the repository or download the script files.

```text
git clone https://github.com/dfirsec/mac_lookup.git
```

2. Navigate to the project directory:

```text
cd mac_lookup
```

3. Install the dependencies using poetry:

```text
poetry install
```

## Usage

1. Create the virtual environment

```text
poetry shell
```

2. Run using the following commands:
   
```text
python mac_lookup.py [-h] [-m MAC] [-f FILE] [-u]
```

- `-h, --help`: Show the help message and exit.
- `-m  MAC, --mac MAC`: MAC address to look up.
- `-f  FILE, --file FILE`: File containing MAC addresses.
- `-u, --update`: Update the local MAC address database.

## Configuration

**OPTIONAL**: Before running the script, set up the necessary configuration:

> Obtain an API key from maclookup.app by signing up on their website. Copy the API key to the `settings.json` file.

## Examples

Look up a single MAC address:

```text
python mac_lookup.py -m 00:00:0C
```

Process a file containing MAC addresses:

```text
python mac_lookup.py -f mac_addresses.txt
```

Update the local MAC address database:

```text
python mac_lookup.py -u
```

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvement, please create an issue or submit a pull request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.