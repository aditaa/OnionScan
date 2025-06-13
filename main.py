"""Tools for scanning and analyzing Tor onion services."""

import os
import socket
import ssl
import json
import re
import hashlib
from io import BytesIO
from urllib.parse import urlparse, urljoin

from functools import lru_cache
import requests
from PIL import Image, UnidentifiedImageError
from bs4 import BeautifulSoup
import stem
import stem.descriptor.remote

_TOR_SESSION = None


def _get_proxy_config():
    """Return Tor proxy host and port, falling back to defaults."""

    host = os.environ.get("TOR_PROXY_HOST")
    port = os.environ.get("TOR_PROXY_PORT")

    if not host:
        host = "127.0.0.1"

    if not port or not str(port).isdigit():
        port = "9050"

    return host, port


def get_tor_session():
    """Return a requests session configured to use the Tor SOCKS proxy."""

    global _TOR_SESSION  # pylint: disable=global-statement
    if _TOR_SESSION is None:
        host, port = _get_proxy_config()
        session = requests.Session()
        proxies = {
            "http": f"socks5h://{host}:{port}",
            "https": f"socks5h://{host}:{port}",
        }
        session.proxies.update(proxies)
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        _TOR_SESSION = session
    return _TOR_SESSION


def fetch_html_via_tor(url, timeout=10):
    """Return HTML and headers from the URL via the Tor proxy."""

    session = get_tor_session()
    try:
        response = session.get(url, timeout=timeout)
        return response.text, response.headers
    except requests.RequestException as exc:
        return None, str(exc)


def check_common_files(onion_url, timeout=10):
    """Check for common sensitive files on the onion service."""

    paths = [
        "/robots.txt",
        "/.git/HEAD",
        "/.env",
        "/admin",
        "/config.php",
        "/server-status",
    ]
    parsed = urlparse(onion_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    session = get_tor_session()
    for path in paths:
        try:
            res = session.get(urljoin(base, path), timeout=timeout)
            if res.status_code == 200:
                findings.append({"path": path, "status": res.status_code})
        except requests.RequestException:
            continue
    return findings


def extract_cert_info(host, timeout=10):
    """Retrieve TLS certificate information for a host."""

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": cert.get("subject", []),
                    "issuer": cert.get("issuer", []),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                }
    except (OSError, ssl.SSLError) as exc:
        return {"error": str(exc)}


def scan_banner(host, port, label, timeout=10):
    """Fetch the service banner for a given port."""

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return {f"{label}_banner": banner}
    except OSError as exc:
        return {"error": str(exc)}


def scan_protocols(host, timeout=10):
    """Scan common service ports and return collected banners."""

    ports = {
        "ssh": 22,
        "ftp": 21,
        "smtp": 25,
        "xmpp": 5222,
        "bitcoin": 8333,
        "irc": 6667,
        "vnc": 5900,
        "mongodb": 27017,
    }
    return {
        f"{label}_info": scan_banner(host, port, label, timeout)
        for label, port in ports.items()
    }


def extract_metadata(headers):
    """Return a subset of response headers with interesting metadata."""

    return {k: v for k, v in headers.items() if k.lower() in ["server", "x-powered-by"]}


def extract_onion_links(html):
    """Extract .onion hyperlinks from HTML."""

    soup = BeautifulSoup(html, "html.parser")
    return list(
        {a["href"] for a in soup.find_all("a", href=True) if ".onion" in a["href"]}
    )


def extract_bitcoin_addresses(html):
    """Find Bitcoin addresses embedded in the HTML."""

    return re.findall(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", html)


def extract_pgp_keys(html):
    """Extract PGP public key blocks from the HTML."""

    return re.findall(
        r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
        html,
        re.DOTALL,
    )


def extract_emails_and_ids(html):
    """Return emails and Google Analytics identifiers found in the HTML."""

    emails = re.findall(r"[\w.-]+@[\w.-]+", html)
    ga_ids = re.findall(r"UA-\d+-\d+", html)
    return {"emails": emails, "google_analytics_ids": ga_ids}


def extract_exif_data_from_images(html, base_url, timeout=5):
    """Download images in the page and return any EXIF metadata found."""

    soup = BeautifulSoup(html, "html.parser")
    results = []
    session = get_tor_session()
    for img in soup.find_all("img"):
        src = img.get("src")
        if src:
            try:
                full_url = urljoin(base_url, src)
                img_data = session.get(full_url, timeout=timeout).content
                image = Image.open(BytesIO(img_data))
                exif = image.getexif()
                if exif:
                    results.append({"src": full_url, "exif": dict(exif)})
            except (requests.RequestException, OSError, UnidentifiedImageError):
                continue
    return results


def html_fingerprint(html):
    """Return a SHA-1 hash of the HTML content."""

    return hashlib.sha1(html.encode()).hexdigest()


@lru_cache(maxsize=1)
def fetch_tor_descriptor():
    """Fetch the first available Tor relay descriptor."""

    try:
        desc = list(stem.descriptor.remote.get_server_descriptors())[0]
        return {
            "nickname": desc.nickname,
            "published": str(desc.published),
            "platform": desc.platform,
            "contact": desc.contact,
        }
    except stem.DescriptorUnavailable as exc:  # type: ignore[attr-defined]
        return {"error": str(exc)}


def scan_service(onion_url, timeout=10):
    """Run a series of checks against the given onion service."""

    result = {
        "url": onion_url,
        "errors": [],
        "metadata": {},
        "linked_onions": [],
        "cert_info": {},
        "exposed_files": [],
        "bitcoin_addresses": [],
        "pgp_keys": [],
        "emails_and_ids": {},
        "exif_data": [],
        "html_sha1": "",
        "tor_descriptor": {},
    }
    html, headers = fetch_html_via_tor(onion_url, timeout)

    if not html:
        result["errors"].append(headers)
        return result

    result["metadata"] = extract_metadata(headers)
    result["linked_onions"] = extract_onion_links(html)
    result["exposed_files"] = check_common_files(onion_url, timeout)
    result["bitcoin_addresses"] = extract_bitcoin_addresses(html)
    result["pgp_keys"] = extract_pgp_keys(html)
    result["emails_and_ids"] = extract_emails_and_ids(html)
    result["exif_data"] = extract_exif_data_from_images(html, onion_url, timeout)
    result["html_sha1"] = html_fingerprint(html)
    result["tor_descriptor"] = fetch_tor_descriptor()

    try:
        hostname = urlparse(onion_url).hostname
        if hostname:
            result["cert_info"] = extract_cert_info(hostname, timeout)
            result.update(scan_protocols(hostname, timeout))
    except (OSError, ssl.SSLError) as exc:
        result["errors"].append(f"Protocol scan error: {str(exc)}")

    return result


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Python version of OnionScan")
    parser.add_argument("onion", help=".onion URL to scan or path to .txt file of URLs")
    parser.add_argument(
        "--output", help="Path to save JSON report", default="scan_report.json"
    )
    parser.add_argument(
        "--timeout", help="Request timeout in seconds", type=int, default=10
    )
    args = parser.parse_args()

    urls = []
    if args.onion.endswith(".txt") and os.path.exists(args.onion):
        with open(args.onion, "r", encoding="utf-8") as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
    else:
        urls = [args.onion]

    all_results = {}
    for target_url in urls:
        print(f"Scanning: {target_url}")
        all_results[target_url] = scan_service(target_url, args.timeout)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"Report saved to {output_path}")
