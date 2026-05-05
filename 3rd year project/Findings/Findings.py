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
    findings = []

    # Protocol
    if protocol != "https":
        findings.append((
            "Unsecured Protocol",
            "The site does not use HTTPS, which makes it easier to spoof or intercept."
        ))

    # Subdomains
    if long_subdomain_chain:
        findings.append((
            "Long Subdomain Chain",
            "Phishing URLs often use deep subdomains to mimic trusted brands."
        ))

    if subdomain_count > 2:
        findings.append((
            f"{subdomain_count} Subdomains",
            "An unusually high number of subdomains can indicate obfuscation."
        ))

    # Suspicious characters
    if suspicious_chars:
        findings.append((
            f"Suspicious Characters: {suspicious_chars}",
            "These characters are often used in obfuscated or deceptive URLs."
        ))

    # Redirection
    if path_redirection:
        findings.append((
            "Redirection Detected",
            "Redirects can hide the final malicious destination."
        ))

    # Blacklist
    if blacklist_hits > 0:
        findings.append((
            "Blacklist Hit",
            "This domain appears in known threat intelligence databases."
        ))

    # Misleading brand terms
    if misleading_brand_terms:
        findings.append((
            f"Misleading Brand Terms: {misleading_brand_terms}",
            "Attackers often impersonate trusted brands to trick users."
        ))

    # Domain penalties
    if domain_penalties:
        if domain_penalties.get("age_penalty", 0) > 0:
            findings.append((
                "Very New Domain",
                "Newly registered domains are frequently used for phishing."
            ))

        if domain_penalties.get("expiration_penalty", 0) > 0:
            findings.append((
                "Domain Expires Soon",
                "Short‑lived domains are often used for malicious activity."
            ))

        if domain_penalties.get("registrar_penalty", 0) > 0:
            findings.append((
                "High‑Risk Registrar",
                "Some registrars are commonly abused by attackers."
            ))

        if domain_penalties.get("ssl_penalty", 0) > 0:
            findings.append((
                "SSL Certificate Issue",
                "Invalid or weak SSL certificates are a red flag."
            ))

    return findings
