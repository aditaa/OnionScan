import requests
import socks
import socket
import ssl
import json
import os
import re
import hashlib
import stem.descriptor.remote
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Setup SOCKS5 proxy for Tor using environment variables or defaults
tor_host = os.getenv("TOR_PROXY_HOST", "127.0.0.1")
tor_port = int(os.getenv("TOR_PROXY_PORT", 9050))
socks.set_default_proxy(socks.SOCKS5, tor_host, tor_port)
socket.socket = socks.socksocket

def fetch_html_via_tor(url, timeout=10):
    headers = ***REMOVED***"User-Agent": "Mozilla/5.0 (compatible; OnionScanner/1.0)"***REMOVED***
    try:
        response = requests.get(url, timeout=timeout, headers=headers)
        return response.text, response.headers
    except requests.exceptions.RequestException as e:
        return None, f"Request error: ***REMOVED***e***REMOVED***"
    except Exception as e:
        return None, f"Unexpected error: ***REMOVED***e***REMOVED***"

def check_common_files(onion_url, timeout=10):
    exposed_files = []
    common_paths = ["/robots.txt", "/.git/HEAD", "/.env", "/admin", "/config.php", "/server-status"]
    for path in common_paths:
        try:
            full_url = onion_url.rstrip('/') + path
            res = requests.get(full_url, timeout=timeout)
            if res.status_code == 200:
                if "<title>Index of /" in res.text:
                    exposed_files.append(***REMOVED***"path": path, "directory_listing": True***REMOVED***)
                else:
                    exposed_files.append(***REMOVED***"path": path, "status": res.status_code***REMOVED***)
        except:
            continue
    return exposed_files

def extract_cert_info(host, timeout=10):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return ***REMOVED***
                    "subject": cert.get("subject", []),
                    "issuer": cert.get("issuer", []),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                ***REMOVED***
    except Exception as e:
        return ***REMOVED***"error": str(e)***REMOVED***

def scan_banner(host, port, label, timeout=10):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return ***REMOVED***f"***REMOVED***label***REMOVED***_banner": banner***REMOVED***
    except Exception as e:
        return ***REMOVED***"error": str(e)***REMOVED***

def scan_protocols(host, timeout=10):
    ports = ***REMOVED***
        "ssh": 22,
        "ftp": 21,
        "smtp": 25,
        "xmpp": 5222,
        "bitcoin": 8333
    ***REMOVED***
    results = ***REMOVED******REMOVED***
    for label, port in ports.items():
        results[f"***REMOVED***label***REMOVED***_info"] = scan_banner(host, port, label, timeout)
    return results

def extract_metadata(headers):
    leaks = ***REMOVED******REMOVED***
    for key in headers:
        if key.lower() in ["server", "x-powered-by"]:
            leaks[key] = headers[key]
    return leaks

def extract_onion_links(html):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for a in soup.find_all('a', href=True):
        if ".onion" in a['href']:
            links.add(a['href'])
    return list(links)

def extract_bitcoin_addresses(html):
    bitcoin_regex = r"[13][a-km-zA-HJ-NP-Z1-9]***REMOVED***25,34***REMOVED***"
    return re.findall(bitcoin_regex, html)

def extract_pgp_keys(html):
    pgp_regex = r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----"
    return re.findall(pgp_regex, html, re.DOTALL)

def extract_exif_data_from_images(html, base_url, timeout=5):
    from PIL import Image
    from io import BytesIO

    soup = BeautifulSoup(html, "html.parser")
    img_tags = soup.find_all("img")
    exif_data = []
    for img in img_tags:
        src = img.get("src")
        if src:
            full_url = urljoin(base_url, src)
            try:
                img_bytes = requests.get(full_url, timeout=timeout).content
                image = Image.open(BytesIO(img_bytes))
                exif = image.getexif()
                if exif:
                    exif_data.append(***REMOVED***"src": full_url, "exif": dict(exif)***REMOVED***)
            except:
                continue
    return exif_data

def html_fingerprint(html):
    return hashlib.sha1(html.encode()).hexdigest()

def fetch_tor_descriptor(onion):
    try:
        desc = list(stem.descriptor.remote.get_server_descriptors())[0]
        return ***REMOVED***
            "nickname": desc.nickname,
            "published": str(desc.published),
            "platform": desc.platform,
            "contact": desc.contact,
        ***REMOVED***
    except Exception as e:
        return ***REMOVED***"error": str(e)***REMOVED***

def scan_service(onion_url, timeout=10):
    result = ***REMOVED***
        "url": onion_url,
      ***REMOVED***],
        "metadata": ***REMOVED******REMOVED***,
      ***REMOVED***
        "cert_info": ***REMOVED******REMOVED***,
      ***REMOVED***
      ***REMOVED***
      ***REMOVED***
      ***REMOVED***
      ***REMOVED***
        "tor_descriptor": ***REMOVED******REMOVED***
    ***REMOVED***
    html, headers = fetch_html_via_tor(onion_url, timeout)

    if not html:
        result["errors"].append(headers)
        return result

    result["metadata"] = extract_metadata(headers)
    result["linked_onions"] = extract_onion_links(html)
    result["exposed_files"] = check_common_files(onion_url, timeout)
    result["bitcoin_addresses"] = extract_bitcoin_addresses(html)
    result["pgp_keys"] = extract_pgp_keys(html)
    result["exif_data"] = extract_exif_data_from_images(html, onion_url, timeout)
    result["html_sha1"] = html_fingerprint(html)
    result["tor_descriptor"] = fetch_tor_descriptor(onion_url)

    try:
        hostname = urlparse(onion_url).hostname
        if hostname:
            result["cert_info"] = extract_cert_info(hostname, timeout)
            result.update(scan_protocols(hostname, timeout))
    except Exception as e:
        result["errors"].append(f"Protocol scan error: ***REMOVED***str(e)***REMOVED***")

    return result

if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Python version of OnionScan")
    parser.add_argument("onion", help=".onion URL to scan")
    parser.add_argument("--output", help="Path to save JSON report", default="scan_report.json")
    parser.add_argument("--timeout", help="Request timeout in seconds", type=int, default=10)
    args = parser.parse_args()

    report = scan_service(args.onion, args.timeout)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to ***REMOVED***output_path***REMOVED***")
