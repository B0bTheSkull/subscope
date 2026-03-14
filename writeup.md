---
title: "SubScope: The Recon Tool I Wish I'd Had on My First Bug Bounty"
date: 2025-04-07
tags: [bug-bounty, recon, subdomain-enumeration, python, web-security]
excerpt: "Good recon is the difference between finding a bug and missing it entirely. SubScope combines certificate transparency, DNS brute force, and HTTP probing in a single pipeline."
---

# SubScope: The Recon Tool I Wish I'd Had on My First Bug Bounty

The first bug bounty program I worked was a disaster — not because I didn't find anything, but because my recon was a mess. I'd manually check crt.sh in one tab, run a quick dig in a terminal, maybe throw subfinder at it if I remembered to install it. By the time I'd pieced together a picture of the target's subdomains, I'd wasted an hour on tooling that should have taken five minutes.

SubScope is the tool I wanted then. It combines three discovery methods into a single pipeline, probes everything it finds over HTTP, and outputs a clean table you can actually reason about.

## Why Subdomain Enumeration Matters

The attack surface of a modern web application isn't one domain. It's dozens of subdomains: development environments, staging servers, internal APIs, admin panels, legacy applications, forgotten demo sites. Each of these is a potential entry point.

Attackers know this. Before they ever look at the main domain, they enumerate subdomains. They're looking for:
- **Dev/staging environments** — often less hardened, sometimes contain real production data
- **Admin panels** — direct access to backend functions, often inadequately secured
- **Forgotten applications** — running old software versions with known CVEs
- **Takeover opportunities** — subdomains pointing to cloud services that are no longer claimed

Good recon means knowing your (or your target's) complete attack surface before you start testing.

## The Discovery Pipeline

SubScope runs three discovery methods in sequence:

### Certificate Transparency

When a TLS certificate is issued for a domain, it's logged in public certificate transparency logs. crt.sh is a search engine for these logs. Querying `%.example.com` returns every subdomain that has ever had a certificate — including subdomains that no longer exist in DNS but might still be interesting.

The crt.sh API returns JSON: each entry has a `name_value` field that can contain multiple domain names (SANs — Subject Alternative Names). SubScope parses all of them, deduplicates, and filters for subdomains of the target domain.

This method has great coverage because developers can't hide it — every public TLS cert ends up in the logs. I've found staging environments on bug bounty programs this way that weren't in any wordlist.

### DNS Brute Force

The built-in wordlist covers the most common subdomain patterns: `api`, `admin`, `dev`, `staging`, `vpn`, `portal`, `grafana`, `jenkins`, `gitlab`, `k8s`, `cdn`, `mail`, and hundreds more. For each word, SubScope tries to resolve `word.domain.com`.

Concurrent resolution with configurable thread count (default 50) makes this fast. A typical 500-word wordlist against a responsive DNS server runs in a few seconds.

Custom wordlists are supported via `--wordlist`. For serious work, I'll use a larger wordlist (SecLists has good ones) alongside the built-in.

### HTTP Probing

DNS resolution tells you a subdomain exists and resolves to an IP. HTTP probing tells you what's actually running on it.

SubScope probes each live subdomain over HTTPS first, falling back to HTTP. For each that responds, it captures:
- HTTP status code (200, 301, 403, 404, etc.)
- Page title (from `<title>` tag)
- Server header (nginx, Apache, etc.)
- Final URL after redirects

The status code is color-coded in the output: green for 200s, cyan for redirects, yellow for 4xx, red for 5xx. Scanning a wide scope, you want to quickly focus on the interesting ones — 200s that aren't just marketing pages, 403s that might have accessible endpoints, 500s that might indicate something worth poking.

## Subdomain Takeover

This is the most satisfying type of finding to discover and report.

A subdomain takeover happens when a subdomain has a CNAME pointing to a third-party service (GitHub Pages, Netlify, Heroku, S3, etc.), but the associated service account has been deleted or the resource isn't claimed. An attacker can then claim that resource themselves and serve arbitrary content from the victim's subdomain.

SubScope's takeover checker reads CNAME records and compares them against a database of 18+ known-vulnerable service fingerprints. If it finds a match, it makes an HTTP request and checks if the response contains the known "unclaimed" fingerprint string.

In bug bounty work, even a "potential" takeover finding (CNAME matches a vulnerable pattern but fingerprint check was inconclusive) is worth manual investigation. Some services vary their error messages.

## The Output

The terminal output is a color-coded table:

```
STATUS   SUBDOMAIN                    IP              SERVER       TITLE
200      api.example.com              93.184.216.34   nginx        API Docs
403      admin.example.com            93.184.216.34   Apache       -
200      staging.example.com          93.184.216.34   nginx        Staging
```

The JSON export includes everything — IP, status, title, server, redirect chain — in a format you can feed into other tools or scripts.

## Running It

```bash
# Install
pip install -r requirements.txt

# Basic scan
python subscope.py --domain example.com

# With takeover check
python subscope.py --domain example.com --takeover-check

# Multiple domains from scope file
python subscope.py --scope scope.txt --output results.json
```

For bug bounty work, I'll typically start with:
```bash
python subscope.py --domain target.com --takeover-check --output target-recon.json --csv target-recon.csv
```

Then I'll review the CSV sorted by status code, look for interesting titles, and dig deeper into anything that stands out.

## What It's Found

On a recent bug bounty program (with permission, obviously):
- A `staging` subdomain running an older version of the application with a debug endpoint exposed
- A `docs` subdomain with a CNAME to an unclaimed GitHub Pages site (confirmed takeover — reported and rewarded)
- An `api-v1` subdomain returning verbose error messages including internal stack traces

None of these would have shown up in a one-time manual check. That's the value of systematic enumeration.

## Responsible Use

Only test domains you own or have explicit authorization to test. Most bug bounty programs have a defined scope — stick to it. Subdomain enumeration is generally considered passive recon and is typically in scope, but read the program rules. When in doubt, ask.

---

*Code: [B0bTheSkull/subscope](https://github.com/B0bTheSkull/subscope)*
