import idna
from urllib.parse import urlparse

def detect_obfuscation(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    query = parsed.query or ""

    results = {
        "unicode_mixed_script": False,
        "subdomain_count": 0,
        "long_subdomain_chain": False,
        "suspicious_chars": [],
        "path_redirection": False,
        "misleading_brand_terms": []
    }

    # Unicode
    try:
        ascii_domain = idna.encode(hostname).decode()
        if ascii_domain != hostname:
            results["unicode_mixed_script"] = True
    except:
        results["unicode_mixed_script"] = True

    # Subdomains
    subdomains = hostname.split(".")
    results["subdomain_count"] = len(subdomains)
    if len(subdomains) >= 5:
        results["long_subdomain_chain"] = True

    # Suspicious characters
    for char in ["@", "-", "~", "..", "#"]:
        if char in url:
            results["suspicious_chars"].append(char)

    url_after_protocol = url.split("://", 1)[-1]
    if "//" in url_after_protocol:
        results["suspicious_chars"].append("//")

    # Redirect in query
    if "http" in query.lower():
        results["path_redirection"] = True

    # Brand impersonation
    known_brands = [
        "paypal", "microsoft", "google", "apple",
        "amazon", "bankofamerica", "chase",
        "facebook", "instagram"
    ]

    for brand in known_brands:
        if brand in hostname.lower() and not hostname.lower().startswith(brand):
            results["misleading_brand_terms"].append(brand)

    return results