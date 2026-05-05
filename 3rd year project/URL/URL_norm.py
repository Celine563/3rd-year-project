from urllib.parse import urlparse, urlunparse, quote, unquote, parse_qs
import idna

def normalise_url(url):
    try:
        parsed = urlparse(url)
    except:
        return None

    #Reject invalid schemes
    if parsed.scheme not in ["http", "https"]:
        return None

    #Must have a hostname
    if not parsed.hostname:
        return None

    #Reject whitespace or backslashes
    if " " in url or "\\" in url:
        return None

    #Hostname must contain at least one dot
    if "." not in parsed.hostname:
        return None

    #IDNA normalize hostname
    try:
        hostname = idna.encode(parsed.hostname.lower()).decode("ascii")
    except idna.IDNAError:
        return None

    #Path
    path = parsed.path or "/"

    #Sort query parameters
    query_dict = parse_qs(parsed.query)
    sorted_query = "&".join(f"{k}={v[0]}" for k, v in sorted(query_dict.items()))

    #Reconstruct normalized URL
    normalized_url = urlunparse((
        parsed.scheme.lower(),
        hostname,
        path,
        parsed.params,
        sorted_query,
        parsed.fragment
    ))

    return normalized_url
