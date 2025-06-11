# PythonOnionScan Wiki

Welcome to the project wiki! This page provides an overview of the repository, how it is structured and how to get started using the tool.

For a more detailed walkthrough of the code itself, see the [Codebase Overview](CodebaseOverview.md) page.

## Repository Structure

```
/OnionScan
├── main.py           # core scanning logic
├── README.md         # basic project information
├── pyproject.toml    # project metadata
├── requirements.txt  # dependencies
├── uv.lock           # lock file for uv
└── scan_report.json  # example scan output
```

All of the scanning features live inside `main.py`. The rest of the files help manage dependencies or document the project.

## Features

* **Fetch HTML via Tor** - Connects through a SOCKS5 proxy to retrieve pages anonymously.
* **Detect exposed files** - Looks for common paths like `/.git/HEAD` or `/admin`.
* **Certificate metadata** - Pulls SSL certificate info when available.
* **Protocol banner scanning** - Captures banners from services such as SSH, FTP, SMTP, and more.
* **Linked onion discovery** - Finds other hidden services linked from the page.
* **Bitcoin, PGP & EXIF** - Extracts Bitcoin addresses, PGP blocks and image metadata.
* **HTML fingerprint** - Computes a SHA‑1 hash of the HTML and fetches Tor descriptor data.

See the [README](../README.md) for a short feature list as well.

## Installation

The project requires Python 3. Run the following to install dependencies:

```bash
pip install -r requirements.txt
```

This will install `requests`, `BeautifulSoup`, `Stem`, `Pillow` and the PySocks module used for Tor support.

## Usage

Run a scan against a single hidden service or a text file of URLs:

```bash
python main.py http://somedomain.onion --timeout 15 --output scan.json
```

* `--timeout` sets the request timeout in seconds (default: 10)
* `--output` specifies the JSON file to write results to (default: `scan_report.json`)

Make sure you have a Tor SOCKS proxy running locally, typically on `127.0.0.1:9050`.

## Next Steps

Here are some ideas if you want to contribute or expand the project:

* **Improve logging and error handling** – the current code often suppresses errors. Robust logging would make troubleshooting easier.
* **Extend protocol checks** – `scan_protocols` looks at a handful of ports; you could add more services or implement version detection.
* **Add unit tests** – the code is a single script right now. Breaking it into modules and adding tests would make future development smoother.
* **Explore Tor internals** – understanding how descriptors and SOCKS proxies work will help you customize scans.

## Legal & Ethical Notice

Scanning onion services may be sensitive. Always ensure you have permission to scan a service and are complying with local laws and policies.

---

Happy scanning!
