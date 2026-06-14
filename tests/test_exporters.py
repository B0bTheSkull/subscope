"""Tests for JSON/CSV export and status colouring."""
import csv
import json

from output import exporters
from output import table


SAMPLE = [
    {"subdomain": "www.example.com", "ip": "1.2.3.4", "status": 200,
     "title": "Home", "server": "nginx", "url": "https://www.example.com",
     "redirect": None},
    {"subdomain": "api.example.com", "ip": "5.6.7.8", "status": 403,
     "title": None, "server": None, "url": "https://api.example.com",
     "redirect": None},
]


def test_to_json_structure(tmp_path):
    out = tmp_path / "out.json"
    data = exporters.to_json("example.com", SAMPLE,
                             takeover_findings=[{"subdomain": "x"}],
                             output_path=str(out))
    assert data["domain"] == "example.com"
    assert data["total_found"] == 2
    assert data["subdomains"] == SAMPLE
    assert data["takeover_findings"] == [{"subdomain": "x"}]
    assert "timestamp" in data
    # file written and re-loadable
    loaded = json.loads(out.read_text())
    assert loaded["total_found"] == 2


def test_to_json_defaults_takeover_to_empty_list():
    data = exporters.to_json("example.com", SAMPLE)
    assert data["takeover_findings"] == []


def test_to_csv_writes_rows_and_handles_none(tmp_path):
    out = tmp_path / "out.csv"
    exporters.to_csv(SAMPLE, str(out))
    rows = list(csv.DictReader(out.read_text().splitlines()))
    assert len(rows) == 2
    assert rows[0]["subdomain"] == "www.example.com"
    # None values are written as empty strings
    assert rows[1]["title"] == ""
    assert rows[1]["server"] == ""


def test_to_csv_empty_results_writes_nothing(tmp_path):
    out = tmp_path / "empty.csv"
    exporters.to_csv([], str(out))
    assert not out.exists()


def test_status_color_buckets():
    assert table.status_color(200) == table.GREEN
    assert table.status_color(301) == table.CYAN
    assert table.status_color(403) == table.YELLOW
    assert table.status_color(404) == table.YELLOW
    assert table.status_color(500) == table.RED
    assert table.status_color(None) == table.GREY
