# PythonOnionScan

A modern Python3 port of the original [OnionScan](https://github.com/s-rah/onionscan) by [@s-rah](https://github.com/s-rah).

This tool allows you to scan `.onion` hidden services for common misconfigurations, metadata leaks, and protocol exposure vulnerabilities—via the Tor network.

---

## 🚀 Features

* 🌐 Fetch HTML via Tor SOCKS5 proxy
* 🔍 Detect common exposed files (`/.git`, `/admin`, etc.)
* 🛡️ Extract SSL certificate metadata
* 🧠 Protocol banner scanning (SSH, FTP, SMTP, XMPP, Bitcoin)
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

Requirements:

* `requests`
* `beautifulsoup4`
* `stem`
* `Pillow`
* `socks`

---

## 🧪 Usage

```bash
python onionscan.py http://somedomain.onion --timeout 15 --output scan.json
```

Options:

* `--timeout` — custom timeout in seconds (default: 10)
* `--output` — path to save report JSON (default: `scan_report.json`)

---

## 💡 Credit

* Based on the incredible work of [Sarah Jamie Lewis](https://github.com/s-rah) via [onionscan](https://github.com/s-rah/onionscan)
* Python port and extensions by the GPTavern community.

---

## 📜 License

MIT License
