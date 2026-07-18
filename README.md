# Crypto — Cryptojacking Detection Scanner

A command-line scanner that checks websites for known **cryptojacking**
script signatures — JavaScript that secretly mines cryptocurrency in a
visitor's browser without their consent, using their CPU on the site
operator's behalf.

## What this is

Around 2017-2019, a service called **Coinhive** made in-browser
cryptomining trivially easy to embed on any website — sites (often
compromised ones) would load `coinhive.min.js`, and every visitor's CPU
would start mining Monero for the site operator, usually without any
disclosure. Coinhive itself shut down in 2019, but several copycat
services followed the same pattern.

This tool scans a page's `<script>` tags — both the `src` attribute (where
externally-loaded miner scripts are referenced) and inline script content
(where mining code is sometimes pasted directly into the page) — against a
list of known cryptojacking script signatures and domains.

It can scan:
- **A single site**, given directly on the command line
- **A list of sites** from a file, one per line

A test page (`testsite/index.html`, included for local testing) embeds a
fake `coinhive.min.js` reference, so you can verify the scanner works
without needing to find a real (and likely long-defunct) cryptojacking
site.

## Tech stack

- Python 3.x
- `requests` — fetching page content
- `beautifulsoup4` — parsing HTML and inspecting `<script>` tags
- `colorama` — colored terminal output

## Setup

```bash
git clone https://github.com/Snitch-1302/Crypto.git
cd Crypto
pip install -r requirements.txt
```

## Usage

Scan a single site:
```bash
python jack.py -u example.com
```

Scan a list of sites from a file (one URL/domain per line):
```bash
python jack.py -f sites.txt
```

By default, SSL certificates are verified. To disable verification for
testing against a self-signed/local server:
```bash
python jack.py -u localhost:8877 --insecure
```

## What I learned / what I'd improve

Revisiting this project, I found the scanner's **core detection logic
never actually worked**, even against its own included test file. The
original code checked a script tag's inline text content
(`soup.find("script", text=regex)`), but the actual cryptojacking
signature in a real-world (and in this project's own test page) script
lives in the **`src` attribute** — `<script src="https://coinhive.min.js">`
has no inline text at all. I verified this directly: running the original
logic against the project's own test file returned `None` every time. The
fix checks both the `src` attribute and inline text, and I confirmed the
fix works by serving the test file locally and scanning it — the fixed
version correctly flags it, and correctly reports a clean page (a
`<script>console.log(...)</script>` with no miner reference) as safe, with
no false positive.

A second, smaller bug: the original exception handling used
`except SSLError or ConnectionError or Timeout:`, which due to Python's
`or` operator only ever catches the first exception type listed —
`ConnectionError` and `Timeout` were silently not being caught at all,
meaning an unreachable site during a multi-site scan would crash the
entire run instead of being reported and skipped. I verified this fix too,
by scanning a list including a deliberately unreachable port alongside a
live one — the fixed version correctly reports the unreachable one as an
error and continues to the next site.

Things I'd improve with more time:
- Expand the signature list — the current one reflects the Coinhive era
  specifically; a production tool would need a continuously updated
  signature/threat-intel feed
- Detect obfuscated/minified inline miner code, not just known
  file/domain names
- Add a JSON/CSV output mode for integrating with other tooling

## Known limitations

- Signature-based detection only catches *known* cryptojacking scripts —
  it won't detect a novel or obfuscated miner using a domain/filename not
  in the list
- Doesn't execute JavaScript, so scripts that dynamically inject a miner
  reference at runtime (rather than having it directly in the initial
  HTML) won't be caught

## Full write-up

The detection bug, how I found and proved it, and what "cryptojacking"
actually is: [Hashnode article link]
