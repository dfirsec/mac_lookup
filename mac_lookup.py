#!/usr/bin/env python3

__author__ = "DFIRSec (@pulsecode)"
__description__ = "Simple script to query for MAC address vendor info"

import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests
from tqdm import tqdm

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
        print("[x] Connection error encountered")


def download_db(path, url):
    try:
        resp = requests.get(url, stream=True)
        if resp.status_code == 200:
            with open(path, 'wb') as db_file:
                for data in tqdm(iterable=resp.iter_content(chunk_size=1024),
                                 desc='[+] Downloading',
                                 ncols=100, unit='KB'):
                    db_file.write(data)
    except (requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            requests.exceptions.ConnectionError,
            requests.exceptions.RequestException):
        print("[x] Download error encountered")


def mac_vend(query):
    resp = connect(MACVEND + query)
    return json.dumps(resp.json()['result'], sort_keys=True, indent=4)


def mac_list(mac_addr):
    if not MACLIST.exists():
        print("[-] Local MAC DB is missing, attempting to download...")
        download_db(MACLIST, MACDB)
    mac_vendor = [json.loads(line) for line in open(MACLIST, 'r', encoding='utf-8')]  # nopep8
    try:
        for mac in mac_vendor:
            match = re.search(REGEX, mac_addr)
            if mac['oui'] == match.group(0).upper():
                print(f"{'Company':12}: {mac['companyName']}")
                print(f"{'Mac Prefix':12}: {mac['oui']}")
                print(f"{'Address':12}: {mac['companyAddress']}")
                print(f"{'Created':12}: {mac['dateCreated']}")
                print(f"{'Updated':12}: {mac['dateUpdated']}")
                print(f"{'Type':12}: {mac['assignmentBlockSize']}")
                break
            else:
                print("[-] No results for", mac_addr)
                break
    except Exception:
        print("[x] Erro querying for", mac_addr)


def main(mac_addr=None, mac_file=None):
    if mac_addr:
        try:
            if ":" or "-" not in mac_addr:
                mac_addr = ':'.join(mac_addr[i:i+2]
                                    for i in range(0, len(mac_addr), 2))
            print("[ Querying macvendors database ]")
            results = json.loads(mac_vend(mac_addr))
            print("." * 32)
            for k, v in results.items():
                print(f"{k.title().replace('_', ' '):12}: {v}")
        except Exception:
            # defaults to local db if query fails
            print("\n== Online query failed ==")
            print("\n[ Switching to local database ]")
            print("." * 32)
            mac_list(mac_addr)

    if mac_file:
        if not os.path.exists(mac_file):
            print(f"\033[31m[error]\033[0m {mac_file} does not exist.")
            sys.exit()
        else:
            with open(mac_file) as f:
                text = [text.strip() for text in f.readlines()]
                for mac_addr in text:
                    if ":" or "-" not in mac_addr:
                        mac_addr = ':'.join(mac_addr[i:i+2]
                                            for i in range(0, len(mac_addr), 2))
                    print("." * 30)
                    try:
                        results = json.loads(mac_vend(mac_addr))
                        for k, v in results.items():
                            print(f"{k.title().replace('_', ' '):12}: {v}")
                    except Exception:
                        # defaults to local db if query fails
                        mac_list(mac_addr)


if __name__ == "__main__":
    banner = fr"""
         __  ______   ______   __                __
        /  |/  /   | / ____/  / /   ____  ____  / /____  ______
       / /|_/ / /| |/ /      / /   / __ \/ __ \/ //_/ / / / __ \
      / /  / / ___ / /___   / /___/ /_/ / /_/ / ,< / /_/ / /_/ /
     /_/  /_/_/  |_\____/  /_____/\____/\____/_/|_|\__,_/ .___/
                                                       /_/
    """

    print(banner)

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mac', help="mac address")
    parser.add_argument('-f', dest='file', help="file with mac addresses")
    args = parser.parse_args()

    if not args.mac or args.file:
        parser.error('\033[33m No action requested, include mac address (-m) or file (-f)\033[0m')  # nopep8

    main(mac_addr=args.mac, mac_file=args.file)
