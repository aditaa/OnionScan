"""Tests for core module utilities."""

import main


def test_get_tor_session_singleton(monkeypatch):
    """Verify get_tor_session returns a cached session."""
    calls = []

    class FakeSession:  # pylint: disable=too-few-public-methods
        """Minimal session mock."""

        def __init__(self):
            calls.append(1)
            self.proxies = {}
            self.headers = {}

    def fake_session():
        return FakeSession()

    monkeypatch.setattr(main.requests, "Session", fake_session)
    monkeypatch.setenv("TOR_PROXY_HOST", "host")
    monkeypatch.setenv("TOR_PROXY_PORT", "1234")
    main.get_tor_session.cache_clear()

    s1 = main.get_tor_session()
    s2 = main.get_tor_session()

    assert s1 is s2
    assert s1.proxies["http"] == "socks5h://host:1234"
    assert len(calls) == 1


def test_check_common_files(monkeypatch):
    """Check that known files are detected properly."""

    class Resp:  # pylint: disable=too-few-public-methods
        """Simple response object."""

        def __init__(self, code):
            self.status_code = code

    class FakeSession:  # pylint: disable=too-few-public-methods
        """Collects requested URLs."""

        def __init__(self):
            self.requested = []

        def get(self, url, timeout=10):  # pylint: disable=unused-argument
            """Record URL and return fake response."""
            self.requested.append(url)
            if url.endswith("/admin"):
                return Resp(200)
            return Resp(404)

    def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(main, "get_tor_session", fake_get_session)

    findings = main.check_common_files("http://x.onion")
    assert {"path": "/admin", "status": 200} in findings


def test_extract_exif_data_from_images(monkeypatch):
    """Ensure EXIF data is extracted from images."""
    html = "<img src='img.png'>"

    class FakeSession:  # pylint: disable=too-few-public-methods
        """Session returning an image."""

        def get(self, _url, timeout=5):  # pylint: disable=unused-argument
            """Return a bytes response."""

            class R:  # pylint: disable=too-few-public-methods
                """Response placeholder."""

                content = b"bytes"

            return R()

    fake_img = type("Img", (), {"getexif": lambda self: {1: 2}})()

    def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(main, "get_tor_session", fake_get_session)

    def fake_open(*_args, **_kwargs):
        return fake_img

    monkeypatch.setattr(main.Image, "open", fake_open)

    result = main.extract_exif_data_from_images(html, "http://a.onion")
    assert result == [{"src": "http://a.onion/img.png", "exif": {1: 2}}]
