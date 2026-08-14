"""Tests for version utilities."""

import pytest

from cveye.utils.version import compare_versions, normalize_version, parse_version, version_in_range


def test_normalize_version():
    """Normalize version strings."""
    assert normalize_version("v1.24.0") == "1.24.0"
    assert normalize_version("nginx/1.24.0") == "1.24.0"
    assert normalize_version("1.24.0") == "1.24.0"


def test_parse_version():
    """Parse valid and invalid version strings."""
    assert parse_version("1.24.0") is not None
    assert parse_version("invalid") is None


def test_compare_versions():
    """Version comparison: -1, 0, 1."""
    assert compare_versions("1.24.0", "1.26.1") == -1
    assert compare_versions("1.26.1", "1.24.0") == 1
    assert compare_versions("1.24.0", "1.24.0") == 0


def test_version_in_range():
    """Version range inclusion check."""
    # 1.24.0 is in [1.20.0, 1.26.1)
    assert version_in_range("1.24.0", start_including="1.20.0", end_excluding="1.26.1")
    # 1.27.0 is not in [1.20.0, 1.26.1)
    assert not version_in_range("1.27.0", start_including="1.20.0", end_excluding="1.26.1")
    # 1.19.0 is not in [1.20.0, 1.26.1)
    assert not version_in_range("1.19.0", start_including="1.20.0", end_excluding="1.26.1")
