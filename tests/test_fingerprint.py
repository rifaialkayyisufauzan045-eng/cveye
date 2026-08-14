"""Tests for technology fingerprint detectors."""

from cveye.web.fingerprint import fingerprint_web, _parse_server_header


def test_nginx_detector_with_version():
    """Nginx with version from Server header."""
    technologies, plugins, themes = fingerprint_web(
        url="http://example.com",
        status_code=200,
        headers={"Server": "nginx/1.24.0"},
        body="",
    )
    names = [t.name for t in technologies]
    assert "Nginx" in names
    nginx = next(t for t in technologies if t.name == "Nginx")
    assert nginx.version == "1.24.0"


def test_nginx_detector_without_version():
    """Nginx without version -> name only."""
    technologies, plugins, themes = fingerprint_web(
        url="http://example.com",
        status_code=200,
        headers={"Server": "nginx"},
        body="",
    )
    names = [t.name for t in technologies]
    assert "Nginx" in names


def test_php_detector():
    """PHP version from X-Powered-By header."""
    technologies, plugins, themes = fingerprint_web(
        url="http://example.com",
        status_code=200,
        headers={"X-Powered-By": "PHP/8.2.12"},
        body="",
    )
    names = [t.name for t in technologies]
    assert "PHP" in names
    php = next(t for t in technologies if t.name == "PHP")
    assert php.version == "8.2.12"
