from urllib.parse import urlparse
from URL import URL_in

def val_url(url):
    try:
       parsed = urlparse(url)
    except:
        return False
    
    if parsed.scheme not in ["http", "https"]:
        return False
    
    if not parsed.hostname:
        return False
    
    if " " in url or "\\" in url:
        return False    
    
    if "." not in parsed.hostname:
        return False
    
    return True

