import main


def test_get_tor_session_singleton(monkeypatch):
    calls = []

    class FakeSession:
        def __init__(self):
            calls.append(1)
            self.proxies = {}
            self.headers = {}

    monkeypatch.setattr(main.requests, "Session", lambda: FakeSession())
    monkeypatch.setenv("TOR_PROXY_HOST", "host")
    monkeypatch.setenv("TOR_PROXY_PORT", "1234")
    main._TOR_SESSION = None

    s1 = main.get_tor_session()
    s2 = main.get_tor_session()

    assert s1 is s2
    assert s1.proxies["http"] == "socks5h://host:1234"
    assert len(calls) == 1


def test_check_common_files(monkeypatch):
    class Resp:
        def __init__(self, code):
            self.status_code = code

    class FakeSession:
        def __init__(self):
            self.requested = []

        def get(self, url, timeout=10):
            self.requested.append(url)
            if url.endswith("/admin"):
                return Resp(200)
            return Resp(404)

    monkeypatch.setattr(main, "get_tor_session", lambda: FakeSession())

    findings = main.check_common_files("http://x.onion")
    assert {"path": "/admin", "status": 200} in findings


def test_extract_exif_data_from_images(monkeypatch):
    html = "<img src='img.png'>"

    class FakeSession:
        def get(self, url, timeout=5):
            class R:
                content = b"bytes"

            return R()

    fake_img = type("Img", (), {"getexif": lambda self: {1: 2}})()
    monkeypatch.setattr(main, "get_tor_session", lambda: FakeSession())
    monkeypatch.setattr(main.Image, "open", lambda *_: fake_img)

    result = main.extract_exif_data_from_images(html, "http://a.onion")
    assert result == [{"src": "http://a.onion/img.png", "exif": {1: 2}}]
