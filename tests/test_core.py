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
    main._TOR_SESSION = None  # pylint: disable=protected-access

    s1 = main.get_tor_session()
    s2 = main.get_tor_session()

    assert s1 is s2
    assert s1.proxies["http"] == "socks5h://host:1234"
    assert len(calls) == 1


def test_get_tor_session_defaults(monkeypatch):
    """Defaults are used when env vars are missing."""

    class FakeSession:  # pylint: disable=too-few-public-methods
        """Simple session stand-in."""

        def __init__(self):
            self.proxies = {}
            self.headers = {}

    def fake_session():
        return FakeSession()

    monkeypatch.setattr(main.requests, "Session", fake_session)
    monkeypatch.delenv("TOR_PROXY_HOST", raising=False)
    monkeypatch.delenv("TOR_PROXY_PORT", raising=False)
    main._TOR_SESSION = None  # pylint: disable=protected-access

    session = main.get_tor_session()

    assert session.proxies["http"] == "socks5h://127.0.0.1:9050"


def test_get_proxy_config_invalid_port(monkeypatch):
    """Invalid ports revert to the default."""

    monkeypatch.setenv("TOR_PROXY_HOST", "host")
    monkeypatch.setenv("TOR_PROXY_PORT", "abc")

    host, port = main._get_proxy_config()  # pylint: disable=protected-access

    assert host == "host"
    assert port == "9050"


def test_get_proxy_config_cli_override(monkeypatch):
    """Command-line overrides should take precedence over env vars."""

    monkeypatch.setenv("TOR_PROXY_HOST", "envhost")
    monkeypatch.setenv("TOR_PROXY_PORT", "1111")
    monkeypatch.setattr(main, "PROXY_HOST", "cli_host", raising=False)
    monkeypatch.setattr(main, "PROXY_PORT", "2222", raising=False)

    host, port = main._get_proxy_config()  # pylint: disable=protected-access

    assert host == "cli_host"
    assert port == "2222"

    monkeypatch.setattr(main, "PROXY_HOST", None, raising=False)
    monkeypatch.setattr(main, "PROXY_PORT", None, raising=False)
    monkeypatch.delenv("TOR_PROXY_HOST", raising=False)
    monkeypatch.delenv("TOR_PROXY_PORT", raising=False)


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


def test_extract_exif_data_bytes(monkeypatch):
    """Bytes values in EXIF data should be hex encoded."""
    html = "<img src='img.png'>"

    class FakeSession:  # pylint: disable=too-few-public-methods
        """Session returning an image."""

        def get(self, _url, timeout=5):  # pylint: disable=unused-argument
            """Return a fake binary response."""

            class R:  # pylint: disable=too-few-public-methods
                """Response placeholder."""

                content = b"bytes"

            return R()

    fake_img = type("Img", (), {"getexif": lambda self: {1: b"abc"}})()

    def fake_get_session():
        return FakeSession()

    monkeypatch.setattr(main, "get_tor_session", fake_get_session)

    def fake_open(*_args, **_kwargs):
        return fake_img

    monkeypatch.setattr(main.Image, "open", fake_open)

    result = main.extract_exif_data_from_images(html, "http://a.onion")
    assert result == [{"src": "http://a.onion/img.png", "exif": {1: "616263"}}]
