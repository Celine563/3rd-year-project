def URL_in(raw_URL):
    cleaned = raw_URL.strip()

    if cleaned == "":
        return "please enter a URL"

    elif cleaned.startswith("http://") or cleaned.startswith("https://"):
        return cleaned
    else:
        return "http://"+cleaned
  
