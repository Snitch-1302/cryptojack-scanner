#!/usr/bin/env python3
"""
jack.py -- a cryptojacking detection scanner.

Cryptojacking is when a website secretly runs cryptocurrency-mining
JavaScript in a visitor's browser without consent, using their CPU to mine
coins for the site operator. This tool checks a page's <script> tags
against a list of known cryptojacking script signatures (both loaded via
`src=` and embedded directly as inline code).
"""

import argparse
import re
import sys

import requests
import bs4
from colorama import Fore, Style, init as colorama_init

colorama_init()

# Known cryptojacking script signatures (domains/filenames historically
# associated with in-browser mining, most notably Coinhive before it shut
# down in 2019, and several copycat services).
MINER_REGEX = re.compile(
    r'coinhive\.min\.js|wpupdates\.github\.io/ping|cryptonight\.asm\.js|'
    r'coin-hive\.com|jsecoin\.com|cryptoloot\.pro|webassembly\.stream|'
    r'ppoi\.org|xmrstudio|webmine\.pro|miner\.start|allfontshere\.press|'
    r'upgraderservices\.cf|vuuwd\.com'
)

DEFAULT_TIMEOUT = 5


def header():
    print(f"\n{Fore.GREEN}==============================================={Style.RESET_ALL}\n")


def find_miner_scripts(html_text):
    """
    Checks every <script> tag in the given HTML for a cryptojacking
    signature, in BOTH places a malicious reference could actually live:

    1. The `src` attribute -- this is where most real cryptojacking scripts
       are loaded from (e.g. <script src="https://coinhive.min.js">).
    2. The tag's inline text content -- for cases where mining code is
       pasted directly into the page rather than loaded externally.

    BUG FIX: the original version only checked inline text content via
    BeautifulSoup's `text=` parameter, via `soup.find("script", text=regex)`.
    That parameter matches a tag's inline text, NOT its `src` attribute --
    so a script loaded the normal way, `<script src="...coinhive.min.js">`,
    with no inline text, was never actually detected. This was verified
    directly: running the original logic against this project's own
    included test file (index.html) returned None every time, meaning the
    scanner's core detection mechanism never worked, even on its own
    intended test case.

    Returns a list of matched script tags (as BeautifulSoup Tag objects).
    """
    soup = bs4.BeautifulSoup(html_text, "html.parser")
    matches = []

    for script in soup.find_all("script"):
        src = script.get("src", "")
        inline_text = script.string or ""

        if MINER_REGEX.search(src) or MINER_REGEX.search(inline_text):
            matches.append(script)

    return matches


def scan_site(url, verify_ssl=True, timeout=DEFAULT_TIMEOUT):
    """
    Fetches a site and checks it for cryptojacking scripts.
    Returns (matches, error_message). error_message is None on success.
    """
    full_url = url if url.startswith(("http://", "https://")) else f"http://{url}"

    try:
        response = requests.get(full_url, verify=verify_ssl, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        # BUG FIX: the original code caught exceptions with
        # `except A or B or C:`, which due to Python operator precedence
        # only ever catches the FIRST exception type (`A`) -- `or` between
        # exception classes evaluates to the first one, since classes are
        # always truthy. `ConnectionError` and `Timeout` were silently NOT
        # being caught at all. Catching the shared base class
        # `requests.exceptions.RequestException` covers all of them
        # correctly in one place.
        return [], f"Could not fetch site: {e}"

    matches = find_miner_scripts(response.text)
    return matches, None


def print_result(site, matches, error):
    if error:
        print(f"{Fore.YELLOW}{site}: {error}{Style.RESET_ALL}")
        return

    if matches:
        print(f"{Fore.RED}{site}: MINER SIGNATURE(S) FOUND{Style.RESET_ALL}")
        for m in matches:
            print(f"  {m}")
    else:
        print(f"{Fore.GREEN}{site}: no known miner signatures found{Style.RESET_ALL}")


def scan_single(url, verify_ssl):
    header()
    matches, error = scan_site(url, verify_ssl=verify_ssl)
    print_result(url, matches, error)
    header()


def scan_multiple(file_path, verify_ssl):
    try:
        with open(file_path, "r") as f:
            sites = [line.strip() for line in f if line.strip()]
    except OSError as e:
        print(f"{Fore.YELLOW}Could not read file: {e}{Style.RESET_ALL}")
        sys.exit(1)

    header()
    for site in sites:
        print(f"Scanning: {site}")
        matches, error = scan_site(site, verify_ssl=verify_ssl)
        print_result(site, matches, error)
        header()


def main():
    parser = argparse.ArgumentParser(
        description="Scan a website (or list of websites) for known cryptojacking script signatures."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="A single site to scan")
    group.add_argument("-f", "--file", help="A file containing a list of sites to scan, one per line")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification (not recommended; use only for testing)",
    )

    args = parser.parse_args()
    requests.packages.urllib3.disable_warnings()  # only relevant if --insecure is used

    verify_ssl = not args.insecure

    if args.url:
        scan_single(args.url, verify_ssl)
    else:
        scan_multiple(args.file, verify_ssl)


if __name__ == "__main__":
    main()
