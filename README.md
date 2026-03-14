# SubScope

> **Subdomain enumeration and asset discovery — combines DNS brute force, certificate transparency, HTTP probing, and takeover detection.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Authorized Use](https://img.shields.io/badge/authorized%20use-only-red?style=flat-square)

> ⚠️ Only test domains you own or have explicit permission to test. Unauthorized subdomain enumeration may violate computer crime laws.

---

## Discovery Methods

| Method | Description |
|--------|-------------|
| **Certificate Transparency** | Queries crt.sh for all subdomains ever issued a TLS cert |
| **DNS Brute Force** | Resolves 500+ common subdomain prefixes concurrently |
| **HTTP Probing** | Checks each live subdomain for status, title, redirect chain |
| **Takeover Detection** | Checks CNAME records against 18+ known-vulnerable service patterns |

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/subscope.git
cd subscope
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic scan
python subscope.py --domain example.com

# Custom wordlist + more threads
python subscope.py --domain example.com --wordlist custom.txt --threads 100

# crt.sh only (faster, no brute force)
python subscope.py --domain example.com --no-bruteforce

# With subdomain takeover check
python subscope.py --domain example.com --takeover-check

# Export results
python subscope.py --domain example.com --output results.json --csv results.csv

# Scope file (multiple domains)
python subscope.py --scope scope.txt --output all.json
```

---

## Example Output

```
╔═══════════════════════════════════════════╗
║        SubScope v1.0                      ║
║  Subdomain Enumeration & Asset Discovery  ║
╚═══════════════════════════════════════════╝

[*] Target: example.com
[*] Querying certificate transparency (crt.sh)...
    Found 34 subdomains via crt.sh
[*] DNS brute forcing (threads=50)...
    Found 12 subdomains via DNS brute force
[*] Total unique live subdomains: 41
[*] HTTP probing 41 subdomains...
    38 responded to HTTP/HTTPS

────────────────────────────────────────────────────────────────────────────────────────────────────
  STATUS   SUBDOMAIN                                     IP                 SERVER               TITLE
────────────────────────────────────────────────────────────────────────────────────────────────────
  200      www.example.com                               93.184.216.34      nginx/1.18.0         Example Domain
  200      api.example.com                               93.184.216.34      nginx/1.18.0         API Documentation
  200      admin.example.com                             93.184.216.34      Apache/2.4.41        Admin Login
  301      blog.example.com                              93.184.216.34      nginx                -
           ↳ https://blog.example.com/
  403      dev.example.com                               93.184.216.34      nginx/1.18.0         -
  200      staging.example.com                           93.184.216.34      nginx/1.18.0         Staging — Example
────────────────────────────────────────────────────────────────────────────────────────────────────
  Total: 38 live subdomains
```

---

## Scope File Format

```
# scope.txt — one domain per line, # for comments
example.com
target-company.com
another-domain.org
```

---

## Takeover Detection

SubScope checks 18+ known-vulnerable CNAME patterns including:

GitHub Pages, Netlify, Heroku, AWS S3, CloudFront, Azure, Fastly, Surge, Bitbucket, Ghost, Shopify, Webflow, Unbounce, ReadMe.io, Pantheon, and more.

```
[!] POTENTIAL SUBDOMAIN TAKEOVER(S) DETECTED:
  ⚠ docs.example.com → example.github.io (GitHub Pages)
    Fingerprint matched: There isn't a GitHub Pages site here
    Status: CONFIRMED VULNERABLE
```

---

## JSON Output

```json
{
  "domain": "example.com",
  "timestamp": "2024-10-15T14:32:01",
  "total_found": 38,
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "ip": "93.184.216.34",
      "status": 200,
      "title": "API Documentation",
      "server": "nginx/1.18.0",
      "url": "https://api.example.com",
      "redirect": null
    }
  ]
}
```

---

## Built-in Wordlist

Includes 500+ common subdomain prefixes: `api`, `admin`, `dev`, `staging`, `vpn`, `portal`, `grafana`, `jenkins`, `gitlab`, `k8s`, `cdn`, `mail`, and many more.

---

## Roadmap

- [ ] Permutation scanning (altdns-style)
- [ ] ASN-based IP range enumeration
- [ ] Integration with Shodan/Censys
- [ ] Passive DNS via SecurityTrails / DNSDB
- [ ] Virtual host scanning

---

## License

MIT
