"""Tests for crt.sh certificate-transparency SAN parsing."""
from unittest.mock import patch, MagicMock

from discovery import cert_transparency


def _mock_response(json_data, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data
    return resp


def test_parses_san_names_and_dedupes():
    entries = [
        {"name_value": "www.example.com\nmail.example.com"},
        {"name_value": "www.example.com"},  # duplicate
        {"name_value": "example.com"},
    ]
    with patch("discovery.cert_transparency.requests.get",
               return_value=_mock_response(entries)):
        result = cert_transparency.query("example.com")
    assert result == {"www.example.com", "mail.example.com", "example.com"}


def test_strips_wildcard_prefix():
    entries = [{"name_value": "*.example.com"}]
    with patch("discovery.cert_transparency.requests.get",
               return_value=_mock_response(entries)):
        result = cert_transparency.query("example.com")
    assert result == {"example.com"}


def test_lowercases_names():
    entries = [{"name_value": "WWW.Example.COM"}]
    with patch("discovery.cert_transparency.requests.get",
               return_value=_mock_response(entries)):
        result = cert_transparency.query("example.com")
    assert result == {"www.example.com"}


def test_excludes_out_of_scope_domains():
    entries = [
        {"name_value": "www.example.com"},
        {"name_value": "evil.com"},
        {"name_value": "notexample.com"},  # endswith example.com but not .example.com
    ]
    with patch("discovery.cert_transparency.requests.get",
               return_value=_mock_response(entries)):
        result = cert_transparency.query("example.com")
    assert result == {"www.example.com"}


def test_rejects_names_with_invalid_chars():
    entries = [
        {"name_value": "valid.example.com"},
        {"name_value": "bad_under_score.example.com"},  # underscore not in [a-z0-9\-\.]
        {"name_value": "has space.example.com"},
    ]
    with patch("discovery.cert_transparency.requests.get",
               return_value=_mock_response(entries)):
        result = cert_transparency.query("example.com")
    assert result == {"valid.example.com"}


def test_non_200_returns_empty_set():
    with patch("discovery.cert_transparency.requests.get",
               return_value=_mock_response([], status=503)):
        result = cert_transparency.query("example.com")
    assert result == set()


def test_network_exception_returns_empty_set():
    with patch("discovery.cert_transparency.requests.get",
               side_effect=Exception("boom")):
        result = cert_transparency.query("example.com")
    assert result == set()
