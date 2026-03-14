"""DNS brute force subdomain enumeration."""
import socket
import concurrent.futures
from pathlib import Path


def resolve(hostname):
    """Try to resolve a hostname. Returns (hostname, ip) or None."""
    try:
        ip = socket.gethostbyname(hostname)
        return (hostname, ip)
    except socket.gaierror:
        return None


def brute(domain, wordlist_path=None, threads=50):
    """
    Brute force subdomains using the provided wordlist.
    Returns dict of {subdomain: ip}.
    """
    if wordlist_path:
        p = Path(wordlist_path)
        if not p.exists():
            print(f"[!] Wordlist not found: {wordlist_path}")
            return {}
        words = p.read_text().splitlines()
    else:
        # Use built-in wordlist
        builtin = Path(__file__).parent.parent / "wordlists" / "subdomains.txt"
        if builtin.exists():
            words = builtin.read_text().splitlines()
        else:
            words = []

    words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
    hostnames = [f"{w}.{domain}" for w in words]

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                hostname, ip = result
                results[hostname] = ip

    return results
