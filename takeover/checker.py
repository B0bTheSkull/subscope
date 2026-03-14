"""Subdomain takeover detection via CNAME fingerprinting."""
import socket
import re

# Known vulnerable CNAME patterns and their associated services
# Format: (regex_pattern, service_name, fingerprint_in_response)
TAKEOVER_SIGNATURES = [
    (r"\.github\.io$", "GitHub Pages", "There isn't a GitHub Pages site here"),
    (r"\.herokudns\.com$", "Heroku", "No such app"),
    (r"\.herokudns\.com$", "Heroku", "herokucdn.com/error-pages/no-such-app"),
    (r"\.netlify\.app$", "Netlify", "Not Found - Request ID"),
    (r"\.netlify\.com$", "Netlify", "Not Found - Request ID"),
    (r"\.s3\.amazonaws\.com$", "AWS S3", "NoSuchBucket"),
    (r"\.s3-website", "AWS S3 Website", "NoSuchBucket"),
    (r"\.fastly\.net$", "Fastly", "Fastly error: unknown domain"),
    (r"\.pantheonsite\.io$", "Pantheon", "The gods are wise"),
    (r"\.surge\.sh$", "Surge", "project not found"),
    (r"\.bitbucket\.io$", "Bitbucket", "Repository not found"),
    (r"\.cloudfront\.net$", "CloudFront", "Bad request"),
    (r"\.azurewebsites\.net$", "Azure", "404 Web Site not found"),
    (r"\.azurefd\.net$", "Azure Front Door", ""),
    (r"unbouncepages\.com$", "Unbounce", "The requested URL was not found"),
    (r"\.readme\.io$", "Readme.io", "Project doesnt exist"),
    (r"\.ghost\.io$", "Ghost", "The thing you were looking for is no longer here"),
    (r"\.myshopify\.com$", "Shopify", "Sorry, this shop is currently unavailable"),
    (r"\.webflow\.io$", "Webflow", "The page you are looking for doesn't exist"),
]


def get_cname(hostname):
    """Get CNAME record for a hostname using socket."""
    try:
        import subprocess
        result = subprocess.run(
            ["dig", "+short", "CNAME", hostname],
            capture_output=True, text=True, timeout=5
        )
        cname = result.stdout.strip().rstrip(".")
        return cname if cname else None
    except Exception:
        return None


def check_takeover(subdomain, ip=None):
    """
    Check if a subdomain is potentially vulnerable to takeover.
    Returns dict with finding if vulnerable, None otherwise.
    """
    cname = get_cname(subdomain)
    if not cname:
        return None

    for pattern, service, fingerprint in TAKEOVER_SIGNATURES:
        if re.search(pattern, cname, re.IGNORECASE):
            # Check if the CNAME resolves and returns the fingerprint
            try:
                import requests, urllib3
                urllib3.disable_warnings()
                r = requests.get(f"https://{subdomain}", timeout=8, verify=False,
                                 headers={"Host": subdomain})
                if fingerprint and fingerprint.lower() in r.text.lower():
                    return {
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": service,
                        "fingerprint_matched": fingerprint,
                        "status": r.status_code,
                        "vulnerable": True
                    }
                elif fingerprint == "":
                    # No fingerprint to check — flag as potential
                    return {
                        "subdomain": subdomain,
                        "cname": cname,
                        "service": service,
                        "fingerprint_matched": None,
                        "vulnerable": "potential"
                    }
            except Exception:
                pass

    return None
