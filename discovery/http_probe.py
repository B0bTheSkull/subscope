"""HTTP probe discovered subdomains for status, title, server header."""
import re
import concurrent.futures
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8
UA = "SubScope/1.0 (+https://github.com/B0bTheSkull/subscope)"
TITLE_RE = re.compile(r'<title[^>]*>([^<]+)</title>', re.IGNORECASE)


def probe_one(subdomain, ip=None):
    """Probe a single subdomain over HTTP and HTTPS."""
    result = {
        "subdomain": subdomain,
        "ip": ip,
        "status": None,
        "title": None,
        "server": None,
        "url": None,
        "redirect": None,
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            r = requests.get(
                url,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": UA}
            )
            result["status"] = r.status_code
            result["url"] = url
            result["server"] = r.headers.get("Server", "")

            # Title
            m = TITLE_RE.search(r.text[:4096])
            if m:
                result["title"] = m.group(1).strip()[:80]

            # Final redirect URL if different
            if r.url != url:
                result["redirect"] = r.url

            break  # Got a response, don't try http if https worked

        except requests.exceptions.SSLError:
            continue  # Try http
        except Exception:
            break

    return result


def probe(subdomains_dict, threads=30):
    """
    Probe all subdomains.
    subdomains_dict: {subdomain: ip}
    Returns list of result dicts.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(probe_one, sub, ip): sub
            for sub, ip in subdomains_dict.items()
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.get("status") is not None:
                results.append(result)

    results.sort(key=lambda x: (x.get("status") or 999))
    return results
