from collector.dedup import url_hash


def test_url_hash_is_64_chars():
    assert len(url_hash("https://example.com/report/1")) == 64


def test_url_hash_is_deterministic():
    url = "https://hackerone.com/reports/123"
    assert url_hash(url) == url_hash(url)


def test_url_hash_differs_for_different_urls():
    assert url_hash("https://example.com/1") != url_hash("https://example.com/2")


def test_url_hash_hex_string():
    result = url_hash("https://example.com")
    assert all(c in "0123456789abcdef" for c in result)
