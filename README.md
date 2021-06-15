# MAC Address Lookup

[![DeepSource](https://deepsource.io/gh/dfirsec/mac_lookup.svg/?label=active+issues&show_trend=true&token=gYA5JUpCySwLi-SMCnfALNiL)](https://deepsource.io/gh/dfirsec/mac_lookup/?ref=repository-badge) ![Generic badge](https://img.shields.io/badge/python-3.7-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

Simple script to query macvendors.co for MAC address info. Option to also read from file containing a list of MAC addresses.

## Installation

```text
git clone https://github.com/dfirsec/mac_lookup.git
cd mac_lookup
pip install -r requirements.txt
```

```console
     __  ______   ______   __                __
    /  |/  /   | / ____/  / /   ____  ____  / /____  ______
   / /|_/ / /| |/ /      / /   / __ \/ __ \/ //_/ / / / __ \
  / /  / / ___ / /___   / /___/ /_/ / /_/ / ,< / /_/ / /_/ /
 /_/  /_/_/  |_\____/  /_____/\____/\____/_/|_|\__,_/ .___/
                                                   /_/

usage: mac_lookup.py [-h] [-f FILE] [-u] MAC

positional arguments:
  MAC         single mac address

optional arguments:
  -h, --help  show this help message and exit
  -f FILE     file with mac addresses
  -u          update local database
```

## Usage

```text
c:\mac_lookup> python mac_lookup.py 48-F1-7F-96-CC-B9
[ Querying macvendors database ]
................................
Company     : Intel Corporate
Mac Prefix  : 48:F1:7F
Address     : Lot 8, Jalan Hi-Tech 2/3,Kulim  Kedah  09000,MY
Start Hex   : 48F17F000000
End Hex     : 48F17FFFFFFF
Country     : None
Type        : MA-L
```

Switches to local database file if online query fails.

```text
c:\mac_lookup> python mac_lookup.py 20:DE:88
[ Querying macvendors database ]

== Online query failed ==

[ Switching to local database ]
................................
[-] Local MAC DB is missing, attempting to download...
[+] Downloading: 1943KB [00:00, 2471.24KB/s]
Company     : IC Realtime Llc
Mac Prefix  : 20:DE:88
Address     : 3050 N Andrews Ave Ext. Pompano Beach FL 33064 US
Created     : 2018-06-25
Updated     : 2018-06-25
Type        : MA-L
```
