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

    # Unicode check
    try:
        ascii_domain = idna.encode(hostname).decode()
        results["unicode_mixed_script"] = ascii_domain != hostname
    except Exception:
        results["unicode_mixed_script"] = True

    # Subdomains 
    subdomains = hostname.split(".") if hostname else []
    results["subdomain_count"] = len(subdomains)

    if len(subdomains) >= 5:
        results["long_subdomain_chain"] = True

    # Suspicious characters
    suspicious_list = ["%", "@", "\\", "..", "~", "#", "&", "$", "?", "=", "<", ">"]

    for char in suspicious_list:
        if char in url:
            results["suspicious_chars"].append(char)

    # extra check for double slash in path 
    url_after_protocol = url.split("://", 1)[-1]
    if "//" in url_after_protocol:
        results["suspicious_chars"].append("//")

    # Redirect shorteners
    redirect_domains = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "buff.ly", "rebrand.ly", "is.gd", "cutt.ly"
    ]

    hostname_lower = hostname.lower()
    if any(rd in hostname_lower for rd in redirect_domains):
        results["path_redirection"] = True

    # Brand impersonation
    known_brands = [
        "paypal", "microsoft", "google", "apple",
        "amazon", "bankofamerica", "chase",
        "facebook", "instagram"
    ]

    for brand in known_brands:
        if brand in hostname_lower:
            results["misleading_brand_terms"].append(brand)

    return results