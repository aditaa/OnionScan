import requests
import socks
import socket
import ssl
import json
import os
from bs4 import BeautifulSoup

# Setup SOCKS5 proxy for Tor using environment variables or defaults
tor_host = os.getenv("TOR_PROXY_HOST", "127.0.0.1")
tor_port = int(os.getenv("TOR_PROXY_PORT", 9050))
socks.set_default_proxy(socks.SOCKS5, tor_host, tor_port)
socket.socket = socks.socksocket


def fetch_html_via_tor(url):
    try:
        response = requests.get(url, timeout=10)
        return response.text, response.headers
    except requests.exceptions.RequestException as e:
        return None, f"Request error: ***REMOVED***e***REMOVED***"
    except Exception as e:
        return None, f"Unexpected error: ***REMOVED***e***REMOVED***"


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


def scan_service(onion_url):
    result = ***REMOVED***"url": onion_url, "errors": [], "metadata": ***REMOVED******REMOVED***, "linked_onions": []***REMOVED***
    html, headers = fetch_html_via_tor(onion_url)

    if not html:
        result["errors"].append(headers)
        return result

    result["metadata"] = extract_metadata(headers)
    result["linked_onions"] = extract_onion_links(html)
    return result


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Python version of OnionScan")
    parser.add_argument("onion", help=".onion URL to scan")
    parser.add_argument("--output", help="Path to save JSON report", default="scan_report.json")
    args = parser.parse_args()

    report = scan_service(args.onion)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to ***REMOVED***output_path***REMOVED***")