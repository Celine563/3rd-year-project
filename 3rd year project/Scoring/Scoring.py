def score_url(
    protocol,
    long_subdomain_chain,
    subdomain_count,
    suspicious_chars,
    path_redirection,
    blacklist_hits,
    reputation_risk,
    misleading_brand_terms,
    domain_penalties=None,
):
    url_penalties = 0

    if protocol != "https":
        url_penalties += 15

    if long_subdomain_chain:
        url_penalties += 15

    if subdomain_count:
        url_penalties += subdomain_count * 3

    if suspicious_chars:
        url_penalties += len(suspicious_chars) * 4

    if path_redirection:
        url_penalties += 15

    if blacklist_hits:
        url_penalties += blacklist_hits * 25

    if misleading_brand_terms:
        url_penalties += len(misleading_brand_terms) * 15

    domain_penalty_score = 0
    if domain_penalties:
        domain_penalty_score = domain_penalties.get("total_penalty", 0) * 1.5

    final_score = 100 - url_penalties - domain_penalty_score
    final_score = max(0, min(int(final_score), 100))

    return final_score