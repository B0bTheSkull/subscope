"""Certificate transparency lookup via crt.sh."""
import re
import requests

CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"
TIMEOUT = 20


def query(domain):
    """Return a set of subdomains found in certificate transparency logs."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, timeout=TIMEOUT, headers={"Accept": "application/json"})
        if r.status_code != 200:
            return subdomains

        entries = r.json()
        for entry in entries:
            name_value = entry.get("name_value", "")
            # name_value can contain multiple names separated by \n
            for name in name_value.split("\n"):
                name = name.strip().lower()
                # Remove wildcard prefix
                if name.startswith("*."):
                    name = name[2:]
                # Only keep subdomains of our target domain
                if name.endswith(f".{domain}") or name == domain:
                    # Basic validation
                    if re.match(r'^[a-z0-9\-\.]+$', name):
                        subdomains.add(name)
    except Exception:
        pass

    return subdomains
