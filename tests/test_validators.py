"""Tests for target validation."""

import pytest

from cveye.utils.validators import TargetValidationError, validate_target


def test_validate_ipv4():
    """IPv4 address validation."""
    target = validate_target("192.168.1.10")
    assert target.ip == "192.168.1.10"


def test_validate_hostname():
    """Hostname validation."""
    target = validate_target("example.com")
    assert target.hostname == "example.com"


def test_validate_url():
    """URL validation."""
    target = validate_target("https://example.com/path")
    assert target.is_url is True
    assert target.hostname == "example.com"
    assert target.scheme == "https"


def test_validate_cidr():
    """CIDR range validation."""
    target = validate_target("192.168.1.0/30")
    assert target.is_cidr is True
    assert target.ips is not None
    assert len(target.ips) > 0


def test_validate_invalid():
    """Empty target raises TargetValidationError."""
    with pytest.raises(TargetValidationError):
        validate_target("")
