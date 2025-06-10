import requests
import socks
import socket
import ssl
import os
import json
import re
import hashlib
from urllib.parse import urlparse, urljoin
from PIL import Image
from io import BytesIO
from bs4 import BeautifulSoup
import stem.descriptor.remote

def fetch_html_via_tor(url, timeout=10):
    socks.set_default_proxy(socks.SOCKS5, os.getenv("TOR_PROXY_HOST", "127.0.0.1"), int(os.getenv("TOR_PROXY_PORT", 9050)))
    socket.socket = socks.socksocket
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        return response.text, response.headers
    except Exception as e:
        return None, str(e)

def check_common_files(onion_url, timeout=10):
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
    for path in paths:
        try:
            res = requests.get(urljoin(base, path), timeout=timeout)
            if res.status_code == 200:
                findings.append({"path": path, "status": res.status_code})
        except Exception:
            continue
    return findings

def extract_cert_info(host, timeout=10):
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
                    "notAfter": cert.get("notAfter")
                }
    except Exception as e:
        return {"error": str(e)}

def scan_banner(host, port, label, timeout=10):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return {f"{label}_banner": sock.recv(1024).decode(errors="ignore").strip()}
    except Exception as e:
        return {"error": str(e)}

def scan_protocols(host, timeout=10):
    ports = {
        "ssh": 22,
        "ftp": 21,
        "smtp": 25,
        "xmpp": 5222,
        "bitcoin": 8333,
        "irc": 6667,
        "vnc": 5900,
        "mongodb": 27017
    }
    return {f"{label}_info": scan_banner(host, port, label, timeout) for label, port in ports.items()}

def extract_metadata(headers):
    return {k: v for k, v in headers.items() if k.lower() in ["server", "x-powered-by"]}

def extract_onion_links(html):
    soup = BeautifulSoup(html, "html.parser")
    return list({a['href'] for a in soup.find_all('a', href=True) if ".onion" in a['href']})

def extract_bitcoin_addresses(html):
    return re.findall(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", html)

def extract_pgp_keys(html):
    return re.findall(r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", html, re.DOTALL)

def extract_emails_and_ids(html):
    emails = re.findall(r"[\w.-]+@[\w.-]+", html)
    ga_ids = re.findall(r"UA-\d+-\d+", html)
    return {"emails": emails, "google_analytics_ids": ga_ids}

def extract_exif_data_from_images(html, base_url, timeout=5):
    soup = BeautifulSoup(html, "html.parser")
    results = []
    for img in soup.find_all("img"):
        src = img.get("src")
        if src:
            try:
                full_url = urljoin(base_url, src)
                img_data = requests.get(full_url, timeout=timeout).content
                image = Image.open(BytesIO(img_data))
                exif = image.getexif()
                if exif:
                    results.append({"src": full_url, "exif": dict(exif)})
            except:
                continue
    return results

def html_fingerprint(html):
    return hashlib.sha1(html.encode()).hexdigest()

def fetch_tor_descriptor(onion):
    try:
        desc = list(stem.descriptor.remote.get_server_descriptors())[0]
        return {
            "nickname": desc.nickname,
            "published": str(desc.published),
            "platform": desc.platform,
            "contact": desc.contact,
        }
    except Exception as e:
        return {"error": str(e)}

def scan_service(onion_url, timeout=10):
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
        "tor_descriptor": {}
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
    result["tor_descriptor"] = fetch_tor_descriptor(onion_url)

    try:
        hostname = urlparse(onion_url).hostname
        if hostname:
            result["cert_info"] = extract_cert_info(hostname, timeout)
            result.update(scan_protocols(hostname, timeout))
    except Exception as e:
        result["errors"].append(f"Protocol scan error: {str(e)}")

    return result

if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Python version of OnionScan")
    parser.add_argument("onion", help=".onion URL to scan or path to .txt file of URLs")
    parser.add_argument("--output", help="Path to save JSON report", default="scan_report.json")
    parser.add_argument("--timeout", help="Request timeout in seconds", type=int, default=10)
    args = parser.parse_args()

    urls = []
    if args.onion.endswith(".txt") and os.path.exists(args.onion):
        with open(args.onion, "r") as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
    else:
        urls = [args.onion]

    all_results = {}
    for url in urls:
        print(f"Scanning: {url}")
        all_results[url] = scan_service(url, args.timeout)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    print(f"Report saved to {output_path}")
