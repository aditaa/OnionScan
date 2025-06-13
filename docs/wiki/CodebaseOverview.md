# Codebase Overview

This page summarizes the overall structure of the `PythonOnionScan` project and explains how the pieces fit together.

## Repository Layout

```
/OnionScan
├── main.py           # core scanning logic
├── README.md         # basic project information
├── pyproject.toml    # project metadata
├── requirements.txt  # dependencies
├── uv.lock           # lock file for uv
└── scan_report.json  # example scan output
```

All scanning functionality lives in **`main.py`**. The remaining files manage dependencies and provide documentation.

## Purpose

`PythonOnionScan` is a light‑weight Python adaptation of the original OnionScan security scanner. It helps find misconfigurations or information leaks on `.onion` services.

## Key Features

- **Fetch HTML through Tor** using a SOCKS5 proxy.
- **Detect exposed files** like `/.git/HEAD` or `/admin`.
- **Extract certificate metadata** when a site presents TLS.
- **Protocol banner scanning** for SSH, FTP, SMTP, XMPP, and other services.
- **Parse linked onion addresses**, Bitcoin addresses, PGP blocks, emails/analytics IDs, and EXIF metadata.
- **Compute an HTML fingerprint** and retrieve Tor descriptor details.

See the [README](../README.md) for the shorter feature list.

## Installation & Dependencies

The project targets Python 3. Install the required packages with:

```bash
pip install -r requirements.txt
```

Dependencies include `requests`, `PySocks`, `Pillow`, `BeautifulSoup`, and `Stem`.

## Main Script (`main.py`)

The scanner logic is contained in `main.py`.

1. **Tor Connection Setup** – `fetch_html_via_tor()` configures a SOCKS proxy
   using `TOR_PROXY_HOST` and `TOR_PROXY_PORT` environment variables. When they
   are unset, defaults of `127.0.0.1` and `9050` are used. A non-numeric
   `TOR_PROXY_PORT` also falls back to `9050`.
2. **Scanning Helpers** – functions like `check_common_files()` and `scan_protocols()` search for exposed paths and capture banners from common service ports.
3. **`scan_service()` Workflow** – orchestrates HTML fetching, certificate extraction, protocol checks, and metadata parsing. Results are collected in a dictionary.
4. **Command-Line Entry** – when invoked directly, the script accepts either a `.onion` URL or a text file of targets. The output is saved to a JSON report.

## Usage

```bash
python main.py http://example.onion --timeout 15 --output scan.json
```

Run this with a local Tor SOCKS proxy (typically `127.0.0.1:9050`) running.

## Points of Interest & Next Steps

- Explore Tor integration and descriptor fetching.
- Extend protocol coverage beyond the default ports.
- Improve error handling and logging.
- Break the code into modules and add tests for easier maintenance.
- Always consider the legal and ethical implications of scanning onion services.

