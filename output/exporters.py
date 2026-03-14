"""JSON and CSV export for SubScope results."""
import csv
import json
from datetime import datetime


def to_json(domain, results, takeover_findings=None, output_path=None):
    data = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "total_found": len(results),
        "subdomains": results,
        "takeover_findings": takeover_findings or []
    }
    if output_path:
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
    return data


def to_csv(results, output_path):
    if not results:
        return
    fieldnames = ["subdomain", "ip", "status", "title", "server", "url", "redirect"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow({k: (v or "") for k, v in r.items()})
