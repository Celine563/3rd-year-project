from urllib.parse import urlparse, parse_qs, unquote

def url_pattern_analysis(url):
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    results = {
        "suspicious_keywords": [],
        "risky_tld": False,
        "encoded_chars_in_path": False,
        "multiple_subdirectories": False,
        "suspicious_query_params": [],
        "url_length": len(url)
    }

    #Suspicious keywords
    keyword_list = [
        "login", "verify", "secure", "update", "confirm",
        "account", "billing", "password", "reset"
    ]
    for kw in keyword_list:
        if kw in url.lower():
            results["suspicious_keywords"].append(kw)

    #Risky TLDs
    risky_tlds = [
        "zip", "xyz", "top", "gq", "ml", "cf", "tk", "work",
        "click", "country", "stream", "download"
    ]
    tld = hostname.split(".")[-1].lower()
    if tld in risky_tlds:
        results["risky_tld"] = True

    #Encoded characters 
    if "%" in path:
        results["encoded_chars_in_path"] = True

    #Multiple subdirectories 
    segments = [seg for seg in path.split("/") if seg]
    if len(segments) >= 4:
        results["multiple_subdirectories"] = True

    #Suspicious querys
    suspicious_params = ["redirect", "url", "next", "dest", "continue"]
    query_dict = parse_qs(query)

    for param in suspicious_params:
        if param in query_dict:
            results["suspicious_query_params"].append(param)

    return results
