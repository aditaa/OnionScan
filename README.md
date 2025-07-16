# PythonOnionScan

[![Tests](https://github.com/aditaa/OnionScan/actions/workflows/tests.yml/badge.svg)](https://github.com/aditaa/OnionScan/actions/workflows/tests.yml)

A modern Python3 port of the original [OnionScan](https://github.com/s-rah/onionscan) by [@s-rah](https://github.com/s-rah).

This tool allows you to scan `.onion` hidden services for common misconfigurations, metadata leaks, and protocol exposure vulnerabilities—via the Tor network.

---

## 🚀 Features

* 🌐 Fetch HTML via Tor SOCKS5 proxy
* 🔍 Detect common exposed files (`/.git`, `/admin`, etc.)
* 🛡️ Extract SSL certificate metadata
* 🧠 Protocol banner scanning (SSH, FTP, SMTP, XMPP, Bitcoin)
* 🌐 DNS lookups for banners and certificates are routed through the Tor proxy
* 🔗 Parse and list all linked `.onion` addresses
* 🪙 Extract embedded Bitcoin addresses
* 🔐 PGP block scanner
* 📷 EXIF metadata from linked images
* 🧬 HTML fingerprint (SHA-1)
* 🛰️ Tor descriptor parsing (via Stem)

---

## 🛠 Installation

```bash
pip install -r requirements.txt
```

On Debian or Ubuntu you can install system packages instead of using `pip`:

```bash
sudo apt install python3-requests python3-pysocks python3-pil \
    python3-bs4 python3-stem
```

Requirements:

* `requests`
* `beautifulsoup4`
* `stem`
* `Pillow`
* `socks`

---

## 🧪 Usage

```bash
python main.py http://somedomain.onion --timeout 15 --output scan.json
```

The script looks for `TOR_PROXY_HOST` and `TOR_PROXY_PORT` environment
variables to configure the SOCKS proxy. You can also provide `--proxy-host` and
`--proxy-port` on the command line to override these. If no values are supplied,
it defaults to `127.0.0.1` and port `9050`. Non-numeric ports fall back to
`9050`.

Options:

* `--timeout` — custom timeout in seconds (default: 10)
* `--output` — path to save report JSON (default: `scan_report.json`)
* `--proxy-host` — Tor proxy host (overrides `TOR_PROXY_HOST`)
* `--proxy-port` — Tor proxy port (overrides `TOR_PROXY_PORT`)

---

## 💡 Credit

* Based on the incredible work of [Sarah Jamie Lewis](https://github.com/s-rah) via [onionscan](https://github.com/s-rah/onionscan)
* Python port and extensions by the GPTavern community.

---

## 📜 License

MIT License
