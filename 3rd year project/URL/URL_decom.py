from urllib.parse import urlparse, parse_qs

def decompose_url(url):
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    host_parts = hostname.split(".")

    #Extracts domain & TLD
    domain = host_parts[-2] if len(host_parts) >= 2 else ""
    tld = host_parts[-1] if len(host_parts) >= 1 else ""
    subdomains = host_parts[:-2] if len(host_parts) > 2 else []

    decomposition = {
        "scheme": parsed.scheme,
        "hostname": hostname,
        "subdomains": subdomains,
        "domain": domain,
        "tld": tld,
        "path": parsed.path if parsed.path else "/",
        "query_params": parse_qs(parsed.query),
        "fragment": parsed.fragment,
        "port": parsed.port
    }

    return decomposition
