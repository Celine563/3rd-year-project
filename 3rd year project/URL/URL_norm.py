from urllib.parse import urlparse, urlunparse, quote, unquote, parse_qs
import idna

def normalise_url(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    # reject invalid schemes
    if parsed.scheme not in ("http", "https"):
        return None

    # must have a hostname
    if not parsed.hostname:
        return None

    # quick sanity check for obvious junk
    if " " in url or "\\" in url:
        return None

    # hostname must contain at least one dot
    if "." not in parsed.hostname:
        return None

    #IDNA normalize hostname
    try:
        hostname = idna.encode(parsed.hostname.lower()).decode("ascii")
    except idna.IDNAError:
        return None

    path = parsed.path
    if not path:
        path = "/"

    #sort query params 
    query_dict = parse_qs(parsed.query)
    sorted_query = "&".join(
        f"{k}={v[0]}" for k, v in sorted(query_dict.items())
    )

    normalized_url = urlunparse((
        parsed.scheme.lower(),
        hostname,
        path,
        parsed.params,
        sorted_query,
        parsed.fragment
    ))

    return normalized_url