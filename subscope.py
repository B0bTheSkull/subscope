#!/usr/bin/env python3
"""
SubScope - Subdomain Enumeration & Asset Discovery
Combines DNS brute force, certificate transparency, HTTP probing, and takeover detection.

⚠️  Only use against domains you own or have authorization to test.
"""

import argparse
import sys
from pathlib import Path

from discovery import dns_brute, cert_transparency, http_probe
from output import table, exporters

RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[91m"
BOLD = "\033[1m"
WHITE = "\033[37m"


def banner():
    print(f"""
{CYAN}╔═══════════════════════════════════════════╗{RESET}
{CYAN}║        SubScope v1.0                      ║{RESET}
{CYAN}║  Subdomain Enumeration & Asset Discovery  ║{RESET}
{CYAN}╚═══════════════════════════════════════════╝{RESET}
""")


def process_domain(domain, args):
    print(f"\n{CYAN}[*]{RESET} Target: {BOLD}{domain}{RESET}")

    all_subdomains = {}  # subdomain -> ip (or None)

    # Step 1: Certificate Transparency
    if not args.no_crt:
        print(f"{CYAN}[*]{RESET} Querying certificate transparency (crt.sh)...")
        crt_subs = cert_transparency.query(domain)
        print(f"    {GREEN}Found {len(crt_subs)} subdomains via crt.sh{RESET}")
        for sub in crt_subs:
            all_subdomains[sub] = None

    # Step 2: DNS Brute Force
    if not args.no_bruteforce:
        wordlist = args.wordlist if args.wordlist else None
        threads = args.threads
        print(f"{CYAN}[*]{RESET} DNS brute forcing (threads={threads})...")
        brute_results = dns_brute.brute(domain, wordlist_path=wordlist, threads=threads)
        print(f"    {GREEN}Found {len(brute_results)} subdomains via DNS brute force{RESET}")
        all_subdomains.update(brute_results)

    # Resolve IPs for crt.sh results that don't have them
    unresolved = [s for s, ip in all_subdomains.items() if ip is None]
    if unresolved:
        print(f"{CYAN}[*]{RESET} Resolving {len(unresolved)} unresolved subdomains...")
        import concurrent.futures, socket
        def resolve_one(sub):
            try:
                return sub, socket.gethostbyname(sub)
            except Exception:
                return sub, None
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            for sub, ip in ex.map(resolve_one, unresolved):
                if ip:
                    all_subdomains[sub] = ip
                else:
                    del all_subdomains[sub]

    if not all_subdomains:
        print(f"{YELLOW}[!] No subdomains found for {domain}{RESET}")
        return [], []

    print(f"{CYAN}[*]{RESET} Total unique live subdomains: {BOLD}{len(all_subdomains)}{RESET}")

    # Step 3: HTTP Probing
    print(f"{CYAN}[*]{RESET} HTTP probing {len(all_subdomains)} subdomains...")
    probed = http_probe.probe(all_subdomains, threads=args.threads)
    print(f"    {GREEN}{len(probed)} responded to HTTP/HTTPS{RESET}")

    # Step 4: Takeover check (optional)
    takeover_findings = []
    if args.takeover_check:
        print(f"{CYAN}[*]{RESET} Checking for subdomain takeover vulnerabilities...")
        from takeover import checker
        for sub in list(all_subdomains.keys()):
            finding = checker.check_takeover(sub)
            if finding:
                takeover_findings.append(finding)
        if takeover_findings:
            print(f"    {RED}⚠ {len(takeover_findings)} potential takeover(s) found!{RESET}")
        else:
            print(f"    {GREEN}No obvious takeover vulnerabilities detected{RESET}")

    return probed, takeover_findings


def main():
    parser = argparse.ArgumentParser(
        description="SubScope — Subdomain enumeration and asset discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subscope.py --domain example.com
  python subscope.py --domain example.com --wordlist custom.txt --threads 100
  python subscope.py --domain example.com --output results.json --csv results.csv
  python subscope.py --scope scope.txt --output all_results.json
  python subscope.py --domain example.com --no-bruteforce   # crt.sh only
  python subscope.py --domain example.com --takeover-check

Only test domains you own or have permission to test.
        """
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--domain", help="Single target domain")
    target.add_argument("--scope", help="Scope file with one domain per line")

    parser.add_argument("--wordlist", "-w", help="Custom wordlist file (default: built-in)")
    parser.add_argument("--threads", "-t", type=int, default=50, help="Thread count (default: 50)")
    parser.add_argument("--no-bruteforce", action="store_true", help="Skip DNS brute force (crt.sh only)")
    parser.add_argument("--no-crt", action="store_true", help="Skip crt.sh lookup")
    parser.add_argument("--takeover-check", action="store_true", help="Check for subdomain takeover")
    parser.add_argument("--output", "-o", help="Write JSON results to file")
    parser.add_argument("--csv", help="Write CSV results to file")

    args = parser.parse_args()

    banner()

    domains = []
    if args.domain:
        domains = [args.domain.lower().strip()]
    else:
        p = Path(args.scope)
        if not p.exists():
            print(f"{RED}[!] Scope file not found: {args.scope}{RESET}")
            sys.exit(1)
        domains = [line.strip().lower() for line in p.read_text().splitlines()
                   if line.strip() and not line.startswith("#")]

    all_results = []
    all_takeover = []

    for domain in domains:
        probed, takeover_findings = process_domain(domain, args)
        all_results.extend(probed)
        all_takeover.extend(takeover_findings)

        table.print_results(probed, domain)
        if takeover_findings:
            table.print_takeover_findings(takeover_findings)

    # Export
    if args.output:
        exporters.to_json(
            domain=", ".join(domains),
            results=all_results,
            takeover_findings=all_takeover,
            output_path=args.output
        )
        print(f"{CYAN}[*]{RESET} JSON saved: {args.output}")

    if args.csv:
        exporters.to_csv(all_results, args.csv)
        print(f"{CYAN}[*]{RESET} CSV saved: {args.csv}")


if __name__ == "__main__":
    main()
