import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
from tqdm import tqdm

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.6"
__description__ = "Simple script to query for MAC address vendor info"

BASE_DIR = Path(__file__).resolve().parent
MACLIST = BASE_DIR.joinpath('macaddress.io-db.json')
REGEX = re.compile(r'(([a-fA-F0-9](:|-)?){6,17})')
MACVEND = 'https://macvendors.co/api/'
MACDB = 'https://macaddress.io/database/macaddress.io-db.json'


def connect(url):
    try:
        resp = requests.get(url, timeout=(5))
        return resp
    except (requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException):
        pass
    except Exception:
        print("\033[31m[x]\033[0m Connection error encountered")


def download_db(path, url):
    try:
        resp = requests.get(url, stream=True)
        if resp.status_code == 200:
            f_size = int(resp.headers.get("Content-Length", 0))
            pbar = tqdm(iterable=resp.iter_content(chunk_size=1024),
                        desc='[+] Downloading',
                        total=f_size,
                        unit="B",
                        unit_scale=True,
                        unit_divisor=1024)
            with open(path, 'wb') as db_file:
                for data in pbar:
                    db_file.write(data)
                    pbar.update(len(data))
    except (requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException):
        print("\033[31m[x]\033[0m Download error encountered")


def mac_vend(query):
    resp = connect(MACVEND + query)
    return json.dumps(resp.json()['result'], sort_keys=True, indent=4)


def mac_list(mac_addr):
    mac_vendor = [json.loads(line) for line in open(MACLIST, 'r', encoding='utf-8')]  # nopep8
    try:
        count = 0
        for mac in mac_vendor:
            match = re.search(REGEX, mac_addr)
            if mac['oui'] == match.group(0).upper():
                print(f"{'MAC Addr':12}: \033[1;36;40m{match.group(0)}\033[0m")
                print(f"{'Company':12}: {mac['companyName']}")
                print(f"{'Mac Prefix':12}: {mac['oui']}")
                print(f"{'Address':12}: {mac['companyAddress']}")
                print(f"{'Created':12}: {mac['dateCreated']}")
                print(f"{'Updated':12}: {mac['dateUpdated']}")
                print(f"{'Type':12}: {mac['assignmentBlockSize']}")
                count += 1
                break
        if not count:
            print(f"\033[33m[-] No results for {mac_addr}\033[0m")
    except Exception:
        print(f"\033[31m[x] Error querying for {mac_addr}\033[0m")


def modified_date(db_file):
    lastmod = os.stat(db_file).st_mtime
    return datetime.strptime(time.ctime(lastmod), "%a %b %d %H:%M:%S %Y")


def main(mac_addr, mac_file, update):
    if not MACLIST.exists():
        print("\033[33m[-] Local MAC DB is missing, attempting to download...\033[0m")  # nopep8
        download_db(MACLIST, MACDB)
        
    if mac_addr:
        try:
            if not any(char in mac_addr for char in ['-', ':']):
                mac_addr = ':'.join(mac_addr[i:i+2]
                                    for i in range(0, len(mac_addr), 2))
            mac_addr = mac_addr.replace('-', ':')
            print("\n\033[1;32;40m[ Querying macvendors database ]\033[0m")
            results = json.loads(mac_vend(mac_addr))

            print("\033[1;30;40m.\033[0m" * 32)
            if 'error' not in results:
                print(f"\033[1;36;40m{'MAC Addr':12}: {mac_addr}\033[0m")
                for k, v in results.items():
                    print(f"{k.title().replace('_', ' '):12}: {v}")
            else:
                print(f"\033[33m[-] No results for {mac_addr}\033[0m")
        except Exception:
            # defaults to local db if query fails
            print("\033[33m\n   == Online query failed ==\033[0m")
            print("\033[1;32;40m\n[ Switching to local database ]\033[0m")
            print("\033[1;30;40m.\033[0m" * 32)
            mac_list(mac_addr)

    if mac_file:
        if not os.path.exists(mac_file):
            print(f"\033[31m[Error]\033[0m {mac_file} does not exist.")
            sys.exit()
        else:
            print("\033[1;32;40m[ Querying macvendors database ]\033[0m")
            with open(mac_file) as f:
                text = [text.strip() for text in f.readlines()]
                for mac_addr in text:
                    if not any(char in mac_addr for char in ['-', ':']):
                        mac_addr = ':'.join(mac_addr[i:i+2]
                                            for i in range(0, len(mac_addr), 2))

                    mac_addr = mac_addr.replace('-', ':')
                    print("\033[1;30;40m.\033[0m" * 32)

                    try:
                        results = json.loads(mac_vend(mac_addr))
                        if 'error' not in results:
                            print(
                                f"\033[1;36;40m{'MAC Addr':12}: {mac_addr}\033[0m")
                            for k, v in results.items():
                                print(f"{k.title().replace('_', ' '):12}: {v}")
                        else:
                            print(
                                f"\033[33m[-] No results for {mac_addr}\033[0m")
                    except Exception:
                        # defaults to local db if query fails
                        mac_list(mac_addr)

    if update:
        try:
            print(f"[+] Last updated: {modified_date(MACLIST)}")
            input("\033[33m[?] Press Enter to continue, or Ctrl-C to cancel...\033")  # nopep8
            print("\033[32m[+] Updating database...\033[0m")  # nopep8
            download_db(MACLIST, MACDB)
        except KeyboardInterrupt:
            print("\n[-] Update canceled")


if __name__ == "__main__":
    banner = fr"""
         __  ______   ______   __                __
        /  |/  /   | / ____/  / /   ____  ____  / /____  ______
       / /|_/ / /| |/ /      / /   / __ \/ __ \/ //_/ / / / __ \
      / /  / / ___ / /___   / /___/ /_/ / /_/ / ,< / /_/ / /_/ /
     /_/  /_/_/  |_\____/  /_____/\____/\____/_/|_|\__,_/ .___/
                                                       /_/
                                                       
                                                v{__version__}
                                                {__author__}
    """

    print(f"\033[36m{banner}\033[0m")

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mac', metavar="MAC ADDRESS",
                        help="single mac address")
    parser.add_argument('-f', dest='file', metavar="FILE",
                        help="file with mac addresses")
    parser.add_argument('-u', dest='update', action='store_true',
                        help="update local database")
    args = parser.parse_args()

    if not (args.mac or args.file or args.update):
        parser.error("\033[33m No action requested: Include mac address (-m) or file (-f) or update (-u)\033[0m")  # nopep8

    main(mac_addr=args.mac, mac_file=args.file, update=args.update)
