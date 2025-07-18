"""Tests for service scanning functionality."""

import main


def test_scan_service(monkeypatch):
    """Verify that scan_service aggregates data correctly."""
    html = "<html></html>"

    def fake_fetch_html_via_tor(_url, _timeout=10):
        return html, {"Server": "Apache"}

    def fake_check_common_files(_url, _timeout=10):
        return [{"path": "/admin", "status": 200}]

    def fake_extract_cert_info(_host, _timeout=10):
        return {"subject": []}

    def fake_scan_protocols(_host, _timeout=10):
        return {"ssh_info": {"ssh_banner": "OpenSSH"}}

    def fake_extract_exif_data_from_images(_html, _base, _timeout=5):
        return []

    def fake_fetch_tor_descriptor():
        return {"nickname": "test"}

    monkeypatch.setattr(main, "fetch_html_via_tor", fake_fetch_html_via_tor)
    monkeypatch.setattr(main, "check_common_files", fake_check_common_files)
    monkeypatch.setattr(main, "extract_cert_info", fake_extract_cert_info)
    monkeypatch.setattr(main, "scan_protocols", fake_scan_protocols)
    monkeypatch.setattr(
        main, "extract_exif_data_from_images", fake_extract_exif_data_from_images
    )
    monkeypatch.setattr(main, "fetch_tor_descriptor", fake_fetch_tor_descriptor)

    result = main.scan_service("http://abc.onion")

    assert result["url"] == "http://abc.onion"
    assert result["metadata"] == {"Server": "Apache"}
    assert result["exposed_files"] == [{"path": "/admin", "status": 200}]
    assert result["cert_info"] == {"subject": []}
    assert result["ssh_info"] == {"ssh_banner": "OpenSSH"}
    assert result["tor_descriptor"] == {"nickname": "test"}


def test_fetch_tor_descriptor_cached(monkeypatch):
    """Ensure cached descriptor prevents repeated downloads."""
    calls = []

    def fake_get_server_descriptors():
        class Desc:  # pylint: disable=too-few-public-methods
            """Minimal descriptor."""

            nickname = "x"
            published = "now"
            platform = "p"
            contact = "c"

        calls.append(1)
        return [Desc]

    monkeypatch.setattr(
        main.stem.descriptor.remote,
        "get_server_descriptors",
        fake_get_server_descriptors,
    )
    main.fetch_tor_descriptor.cache_clear()
    main.fetch_tor_descriptor()
    main.fetch_tor_descriptor()
    assert len(calls) == 1


def test_fetch_tor_descriptor_empty(monkeypatch):
    """Function should return an error if no descriptors are fetched."""

    def fake_get_server_descriptors():
        return []

    monkeypatch.setattr(
        main.stem.descriptor.remote,
        "get_server_descriptors",
        fake_get_server_descriptors,
    )
    main.fetch_tor_descriptor.cache_clear()
    result = main.fetch_tor_descriptor()
    assert "error" in result
