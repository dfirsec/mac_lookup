import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
from tqdm import tqdm

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.9"
__description__ = "Simple script to query for MAC address vendor info"

# required paths
parent = Path(__file__).resolve().parent
macdb_path = parent.joinpath("macaddress.io-db.json")
macdb_web = "https://macaddress.io/database/macaddress.io-db.json"
macvend = "https://macvendors.co/api/"


def connect(url):
    try:
        session = requests.Session()
        ua = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/43.0"}
        resp = session.get(url, headers=ua)
        return resp
    except (
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
        requests.exceptions.ConnectionError,
        requests.exceptions.RequestException,
    ):
        print("\033[31m[x]\033[0m Connection error encountered")


def download_db(path, url):
    resp = connect(url)
    if resp.status_code == 200:
        size = int(resp.headers.get("Content-Length", 0))
        pbar = tqdm(
            iterable=resp.iter_content(chunk_size=1024),
            desc="[+] \u001b[35mDownloading\033[0m",
            total=size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
        )
        with open(path, "wb") as db_file:
            for data in pbar:
                db_file.write(data)
                pbar.update(len(data))


def mac_vend(query):
    resp = connect(macvend + query)
    return json.dumps(resp.json()["result"], sort_keys=True, indent=4)


def mac_db():
    try:
        mac_vendor = [json.loads(line) for line in open(macdb_path, encoding="utf-8")]
    except json.decoder.JSONDecodeError:
        sys.exit(f"Error encountered reading mac db file.")
    else:
        return mac_vendor


def fix_mac_addr(mac_addr):
    if not any(char in mac_addr for char in ["-", ":"]):
        mac_addr = ":".join(mac_addr[i : i + 2] for i in range(0, len(mac_addr), 2))
    else:
        mac_addr = mac_addr.replace("-", ":")
    return mac_addr


def check_loc_db(mac_addr):
    try:
        match = next(item for item in mac_db() if item["oui"] == mac_addr)
    except StopIteration:
        return False
    else:
        return match


def modified_date(db_file):
    lastmod = os.stat(db_file).st_mtime
    return datetime.strptime(time.ctime(lastmod), "%a %b %d %H:%M:%S %Y")


def main(mac_addr, mac_file, update):
    if not macdb_path.exists():
        print("[-]\033[33m Local MAC DB is missing, attempting to download...\033[0m")
        download_db(macdb_path, macdb_web)

    # single mac address
    if mac_addr:
        print("\033[1;32;40m\n[ Querying local database ]\033[0m")
        print("\033[1;30;40m.\033[0m" * 32)
        mac_addr = fix_mac_addr(mac_addr)
        match = check_loc_db(mac_addr)
        if match:
            print(f"{'MAC Addr':12}: \033[1;36;40m{match['oui']}\033[0m")
            print(f"{'Company':12}: {match['companyName']}")
            print(f"{'Mac Prefix':12}: {match['oui']}")
            print(f"{'Address':12}: {match['companyAddress']}")
            print(f"{'Created':12}: {match['dateCreated']}")
            print(f"{'Updated':12}: {match['dateUpdated']}")
            print(f"{'Type':12}: {match['assignmentBlockSize']}")
        else:
            print(f"[-]\033[33m No results for {mac_addr}\033[0m")

            print("\n\033[1;32;40m[ Querying macvendors online database ]\033[0m")
            print("\033[1;30;40m.\033[0m" * 32)
            results = json.loads(mac_vend(mac_addr))
            if "error" not in results:
                print(f"\033[1;36;40m{'MAC Addr':12}: {mac_addr}\033[0m")
                for k, v in results.items():
                    print(f"{k.title().replace('_', ' '):12}: {v}")
            else:
                print(f"[-]\033[33m No results for {mac_addr}\033[0m")

    # file with list of mac addresses
    if mac_file:
        if not Path(mac_file).exists():
            print(f"\033[31m[Error]\033[0m {mac_file} does not exist.")
            sys.exit()
        else:
            print("\033[1;32;40m[ Querying macvendors database ]\033[0m")
            with open(mac_file) as f:
                text = [text.strip() for text in f.readlines()]

            no_db_match = []
            for addr in text:
                print("\033[1;30;40m.\033[0m" * 32)
                mac_addr = fix_mac_addr(addr)
                match = check_loc_db(mac_addr)
                if match:
                    print(f"{'MAC Addr':12}: \033[1;36;40m{match['oui']}\033[0m")
                    print(f"{'Company':12}: {match['companyName']}")
                    print(f"{'Mac Prefix':12}: {match['oui']}")
                    print(f"{'Address':12}: {match['companyAddress']}")
                    print(f"{'Created':12}: {match['dateCreated']}")
                    print(f"{'Updated':12}: {match['dateUpdated']}")
                    print(f"{'Type':12}: {match['assignmentBlockSize']}")
                else:
                    print(f"[-]\033[33m No results for {mac_addr}\033[0m")
                    no_db_match.append(mac_addr)

            if no_db_match:
                print("\n\033[1;32;40m[ Querying macvendors online database ]\033[0m")
                for mac_addr in no_db_match:
                    print("\033[1;30;40m.\033[0m" * 32)
                    results = json.loads(mac_vend(mac_addr))
                    if "error" not in results:
                        print(f"\033[1;36;40m{'MAC Addr':12}: {mac_addr}\033[0m")
                        for k, v in results.items():
                            print(f"{k.title().replace('_', ' '):12}: {v}")
                    else:
                        print(f"[-]\033[33m No results for {mac_addr}\033[0m")

    # update the local mac db
    if update:
        try:
            print(f"[+] Last updated: {modified_date(macdb_path)}")
            input("[?]\033[33m Press Enter to continue, or Ctrl-C to cancel...\033[0m")
            print("[+]\033[32m Updating database...\033[0m")
            download_db(macdb_path, macdb_web)
        except KeyboardInterrupt:
            print("\n[-]\033[33m Update canceled\033[0m")


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
    parser.add_argument("-m", "--mac", metavar="MAC", help="single mac address")
    parser.add_argument("-f", dest="file", metavar="FILE", help="file with mac addresses")
    parser.add_argument("-u", dest="update", action="store_true", help="update local database")
    args = parser.parse_args()

    if not (args.mac or args.file or args.update):
        parser.error("\033[33m No action requested: Include mac address (-m) or file (-f) or update (-u)\033[0m")

    main(mac_addr=args.mac, mac_file=args.file, update=args.update)
