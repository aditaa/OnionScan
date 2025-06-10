import pytest
from main import (
    html_fingerprint,
    extract_onion_links,
    extract_bitcoin_addresses,
    extract_pgp_keys,
    extract_emails_and_ids,
    extract_metadata
)


def test_html_fingerprint():
    html = '<html><body>Hello World</body></html>'
    expected = 'd54b7b623983de5b6880519382f60059f00539d4'
    assert html_fingerprint(html) == expected


def test_extract_onion_links():
    html = '<a href="http://abc.onion/page">link</a><a href="https://example.com">x</a>'
    links = extract_onion_links(html)
    assert links == ['http://abc.onion/page']


def test_extract_bitcoin_addresses():
    html = 'Donate: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT and 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'
    addrs = extract_bitcoin_addresses(html)
    assert '1BoatSLRHtKNngkdXEeobR76b53LETtpyT' in addrs
    assert '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy' in addrs


def test_extract_pgp_keys():
    block = '-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----'
    html = f'<pre>{block}</pre>'
    keys = extract_pgp_keys(html)
    assert keys == [block]


def test_extract_emails_and_ids():
    html = 'Email me at user@example.com UA-1234-5'
    result = extract_emails_and_ids(html)
    assert result['emails'] == ['user@example.com']
    assert result['google_analytics_ids'] == ['UA-1234-5']


def test_extract_metadata():
    headers = {'Server': 'Apache', 'X-Powered-By': 'PHP', 'Other': 'value'}
    meta = extract_metadata(headers)
    assert meta == {'Server': 'Apache', 'X-Powered-By': 'PHP'}


