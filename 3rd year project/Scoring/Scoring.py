def score_url(
    protocol,
    long_subdomain_chain,
    subdomain_count,
    suspicious_chars,
    path_redirection,
    reputation_risk,
    blacklist_hits,
    misleading_brand_terms,
    domain_penalties=None,
):
    url_penalties = 0

    if protocol != "https":
        url_penalties += 10

    if long_subdomain_chain:
        url_penalties += 10

    url_penalties += subdomain_count * 2
    url_penalties += len(suspicious_chars) * 3

    if path_redirection:
        url_penalties += 10

    url_penalties += reputation_risk
    url_penalties += blacklist_hits * 20
    url_penalties += len(misleading_brand_terms) * 10

    domain_penalty_score = 0
    if domain_penalties and "total_penalty" in domain_penalties:
        domain_penalty_score = domain_penalties["total_penalty"]

    base_score = 100
    final_score = base_score - url_penalties - domain_penalty_score



    return min(final_score, 100)

