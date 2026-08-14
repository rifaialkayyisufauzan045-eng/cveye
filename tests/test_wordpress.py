"""Tests for WordPress detection."""

from cveye.web.wordpress import detect_wordpress


def test_wordpress_generator():
    """Detect WordPress via generator meta tag."""
    html = '<meta name="generator" content="WordPress 6.5.3" />'
    wp, plugins, themes = detect_wordpress(html, {}, "http://example.com")
    assert wp is not None
    assert wp.name == "WordPress"
    assert wp.version == "6.5.3"


def test_wordpress_signature():
    """Detect WordPress via wp-content path."""
    html = '<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">'
    wp, plugins, themes = detect_wordpress(html, {}, "http://example.com")
    assert wp is not None


def test_wordpress_plugin_detection():
    """Detect WordPress plugins via asset URLs."""
    html = '<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.21.0"></script>'
    wp, plugins, themes = detect_wordpress(html, {}, "http://example.com")
    assert len(plugins) > 0
    plugin_names = [p.name.lower() for p in plugins]
    assert any("elementor" in n for n in plugin_names)


def test_no_wordpress():
    """Non-WordPress page returns None."""
    html = "<html><body><h1>Hello World</h1></body></html>"
    wp, plugins, themes = detect_wordpress(html, {}, "http://example.com")
    assert wp is None
