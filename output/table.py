"""Terminal table output for SubScope results."""

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BLUE = "\033[34m"
WHITE = "\033[37m"
GREY = "\033[90m"


def status_color(status):
    if status is None:
        return GREY
    if 200 <= status < 300:
        return GREEN
    if 300 <= status < 400:
        return CYAN
    if status == 403:
        return YELLOW
    if 400 <= status < 500:
        return YELLOW
    if status >= 500:
        return RED
    return WHITE


def print_results(results, domain):
    if not results:
        print(f"{YELLOW}[!] No live subdomains found.{RESET}")
        return

    print(f"\n{BOLD}{'─'*100}{RESET}")
    print(f"  {'STATUS':<8} {'SUBDOMAIN':<45} {'IP':<18} {'SERVER':<20} TITLE")
    print(f"{'─'*100}{RESET}")

    for r in results:
        sub = r.get("subdomain", "?")
        ip = r.get("ip") or r.get("ip", "-")
        status = r.get("status")
        title = (r.get("title") or "-")[:45]
        server = (r.get("server") or "-")[:18]
        redirect = r.get("redirect")

        scolor = status_color(status)
        status_str = str(status) if status else "---"

        # Truncate subdomain for display
        sub_display = sub if len(sub) <= 43 else sub[:40] + "..."

        print(f"  {scolor}{status_str:<8}{RESET} {CYAN}{sub_display:<45}{RESET} {WHITE}{ip:<18}{RESET} {GREY}{server:<20}{RESET} {title}")

        if redirect and redirect != f"https://{sub}" and redirect != f"http://{sub}":
            print(f"  {GREY}{'':8} ↳ {redirect}{RESET}")

    print(f"{BOLD}{'─'*100}{RESET}")
    print(f"  {GREEN}Total: {len(results)} live subdomains{RESET}\n")


def print_takeover_findings(findings):
    if not findings:
        return
    print(f"\n{RED}{BOLD}[!] POTENTIAL SUBDOMAIN TAKEOVER(S) DETECTED:{RESET}")
    for f in findings:
        print(f"  {RED}⚠{RESET} {f['subdomain']} → {f['cname']} ({f['service']})")
        if f.get("fingerprint_matched"):
            print(f"    Fingerprint matched: {f['fingerprint_matched']}")
        vuln = f.get("vulnerable")
        if vuln is True:
            print(f"    {RED}Status: CONFIRMED VULNERABLE{RESET}")
        else:
            print(f"    {YELLOW}Status: POTENTIAL (needs manual verification){RESET}")
    print()
