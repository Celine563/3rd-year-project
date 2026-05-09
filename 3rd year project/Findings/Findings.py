def findings(
    protocol,
    long_subdomain_chain,
    subdomain_count,
    suspicious_chars,
    path_redirection,
    blacklist_hits,
    misleading_brand_terms,
    domain_penalties
):
    results = []

    if protocol != "https":
        results.append(("Unsecured Protocol",
                        "The site does not use HTTPS, which makes it easier to spoof or intercept."))

    if long_subdomain_chain:
        results.append(("Long Subdomain Chain",
                        "Phishing URLs often use deep subdomains to mimic trusted brands."))

    if subdomain_count >= 6:
        results.append(("Excessive Subdomains",
                        "An unusually high number of subdomains can indicate obfuscation."))

    if suspicious_chars:
        results.append((f"Suspicious Characters: {suspicious_chars}",
                        "These characters can be used in deceptive or obfuscated URLs."))

    if path_redirection:
        results.append(("Redirection Detected",
                        "Redirects can hide the final malicious destination."))

    if blacklist_hits > 0:
        results.append(("Blacklist Hit",
                        "This domain appears in known threat intelligence databases."))

    if misleading_brand_terms:
        results.append((f"Misleading Brand Terms: {misleading_brand_terms}",
                        "Impersonation of trusted brands is a common phishing tactic."))

    if domain_penalties:
        if domain_penalties.get("age_penalty", 0) != 0:
            results.append(("Very New Domain", "Recently registered domains are often used for phishing."))

        if domain_penalties.get("expiration_penalty", 0) != 0:
            results.append(("Domain Expires Soon", "Short-lived domains are commonly used in scams."))

        if domain_penalties.get("registrar_penalty", 0) != 0:
            results.append(("High-Risk Registrar", "Some registrars are frequently abused."))

        if domain_penalties.get("ssl_penalty", 0) != 0:
            results.append(("SSL Certificate Issue", "Weak or invalid SSL certificates are a red flag."))

        if domain_penalties.get("domain_name_penalty", 0) != 0:
            results.append(("Suspicious Domain Name", "This domain matches known phishing naming patterns."))

        if domain_penalties.get("hosting_penalty", 0) != 0:
            results.append(("Risky Hosting Platform", "Free or disposable hosting providers are commonly abused."))
    return results
