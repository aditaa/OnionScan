"""Tools for scanning and analyzing Tor onion services."""

import os
import ssl
from pprint import pprint
import re
import hashlib
from io import BytesIO
from urllib.parse import urlparse, urljoin

from functools import lru_cache
import requests
import socks
from PIL import Image, UnidentifiedImageError
from bs4 import BeautifulSoup
import stem
import stem.descriptor.remote

_TOR_SESSION = None

# Optional override for the Tor proxy address configured via CLI
PROXY_HOST = None
PROXY_PORT = None


def _get_proxy_config():
    """Return Tor proxy host and port, falling back to defaults."""

    host = PROXY_HOST or os.environ.get("TOR_PROXY_HOST")
    port = PROXY_PORT or os.environ.get("TOR_PROXY_PORT")

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
    proxy_host, proxy_port = _get_proxy_config()
    try:
        with socks.socksocket() as sock:
            sock.set_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
            sock.settimeout(timeout)
            sock.connect((host, 443))
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": cert.get("subject", []),
                    "issuer": cert.get("issuer", []),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                }
    except (OSError, ssl.SSLError, socks.ProxyError) as exc:
        return {"error": str(exc)}


def scan_banner(host, port, label, timeout=10):
    """Fetch the service banner for a given port."""

    proxy_host, proxy_port = _get_proxy_config()
    try:
        with socks.socksocket() as sock:
            sock.set_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return {f"{label}_banner": banner}
    except OSError as exc:
        if "Connection refused" in str(exc):
            return {"status": "closed"}
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
        if not src:
            continue
        full_url = urljoin(base_url, src)
        try:
            img_data = session.get(full_url, timeout=timeout).content
        except requests.RequestException:
            continue
        try:
            image = Image.open(BytesIO(img_data))
        except (OSError, UnidentifiedImageError):
            continue
        exif = image.getexif()
        if not exif:
            continue
        cleaned = {
            tag: (val.hex() if isinstance(val, bytes) else val)
            for tag, val in exif.items()
        }
        results.append({"src": full_url, "exif": cleaned})
    return results


def html_fingerprint(html):
    """Return a SHA-1 hash of the HTML content."""

    return hashlib.sha1(html.encode()).hexdigest()


@lru_cache(maxsize=1)
def fetch_tor_descriptor():
    """Fetch the first available Tor relay descriptor."""

    try:
        descriptors = list(stem.descriptor.remote.get_server_descriptors())
        if not descriptors:
            raise IndexError("no descriptors")
        desc = descriptors[0]
        return {
            "nickname": desc.nickname,
            "published": str(desc.published),
            "platform": desc.platform,
            "contact": desc.contact,
        }
    except (stem.DescriptorUnavailable, IndexError) as exc:  # type: ignore[attr-defined]
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

    parser = argparse.ArgumentParser(description="Python version of OnionScan")
    parser.add_argument("onion", help=".onion URL to scan or path to .txt file of URLs")
    parser.add_argument(
        "--timeout", help="Request timeout in seconds", type=int, default=10
    )
    parser.add_argument("--proxy-host", help="Tor proxy host")
    parser.add_argument("--proxy-port", help="Tor proxy port")
    args = parser.parse_args()

    # Override proxy settings if provided on the command line
    if args.proxy_host:
        PROXY_HOST = args.proxy_host
    if args.proxy_port:
        PROXY_PORT = args.proxy_port

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

    pprint(all_results)
