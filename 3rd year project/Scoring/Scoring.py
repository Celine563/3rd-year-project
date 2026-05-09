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
    domain_penalty_score = 0
#URL penalties
    if not protocol or protocol != "https":
        url_penalties += 15 
#
    if long_subdomain_chain:
        url_penalties += 15 

    url_penalties += subdomain_count * 3 
    url_penalties += len(suspicious_chars) * 4 

    if path_redirection:
        url_penalties += 15

    url_penalties += blacklist_hits * 25
    url_penalties += len(misleading_brand_terms) * 15

#Domain penalties
    if domain_penalties and "total_penalty" in domain_penalties:
        domain_penalty_score = domain_penalties["total_penalty"]

    if not domain_penalties:
        domain_penalty_score = 0
    else:
        domain_penalty_score = domain_penalties.get("total_penalty", 0) * 1.5

    base_score = 100
    final_score = base_score - url_penalties - domain_penalty_score

    final_score = int(max(min(final_score, 100), 0))
    return final_score