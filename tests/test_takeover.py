"""Tests for CNAME-fingerprint subdomain-takeover detection."""
import re
from unittest.mock import patch, MagicMock

from takeover import checker


def test_signatures_are_valid_regexes():
    for pattern, service, fingerprint in checker.TAKEOVER_SIGNATURES:
        re.compile(pattern)  # raises if invalid
        assert service


def test_no_cname_returns_none():
    with patch("takeover.checker.get_cname", return_value=None):
        assert checker.check_takeover("sub.example.com") is None


def test_cname_without_matching_signature_returns_none():
    with patch("takeover.checker.get_cname", return_value="something.cloudprovider.example"):
        assert checker.check_takeover("sub.example.com") is None


def _http_resp(text, status=404):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    return resp


def test_confirmed_vulnerable_when_fingerprint_matches():
    with patch("takeover.checker.get_cname", return_value="myapp.github.io"), \
         patch("requests.get",
               return_value=_http_resp("There isn't a GitHub Pages site here.")):
        finding = checker.check_takeover("sub.example.com")
    assert finding is not None
    assert finding["vulnerable"] is True
    assert finding["service"] == "GitHub Pages"
    assert finding["cname"] == "myapp.github.io"


def test_not_vulnerable_when_fingerprint_absent():
    with patch("takeover.checker.get_cname", return_value="myapp.github.io"), \
         patch("requests.get",
               return_value=_http_resp("Welcome to my live site")):
        assert checker.check_takeover("sub.example.com") is None


def test_empty_fingerprint_flags_potential():
    # Azure Front Door signature has an empty fingerprint -> "potential"
    with patch("takeover.checker.get_cname", return_value="myapp.azurefd.net"), \
         patch("requests.get", return_value=_http_resp("anything")):
        finding = checker.check_takeover("sub.example.com")
    assert finding is not None
    assert finding["vulnerable"] == "potential"
    assert finding["service"] == "Azure Front Door"


def test_fingerprint_match_is_case_insensitive_on_cname():
    with patch("takeover.checker.get_cname", return_value="MyApp.GitHub.IO"), \
         patch("requests.get",
               return_value=_http_resp("THERE ISN'T A GITHUB PAGES SITE HERE")):
        finding = checker.check_takeover("sub.example.com")
    assert finding is not None
    assert finding["vulnerable"] is True


def test_http_error_during_probe_returns_none():
    with patch("takeover.checker.get_cname", return_value="myapp.github.io"), \
         patch("requests.get", side_effect=Exception("timeout")):
        assert checker.check_takeover("sub.example.com") is None
