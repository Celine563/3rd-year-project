from flask import Flask, render_template, request
from URL.URL_in import URL_in
from URL.URL_val import val_url
from URL.URL_norm import normalise_url
from URL.URL_decom import decompose_url
from URL.URL_patt import url_pattern_analysis
from URL.URL_detect_obfus import detect_obfuscation
from BlackList.Global_blacklist import check_url_against_public_blacklists
from Scoring.Scoring import score_url
from Domain.Domain_analysis import run_full_analysis
from Findings.Findings import findings


app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    blacklist_hits = 0
    reputation_risk = 0
    context = {
        "url": "",
        "format_status": "",
        "validation_status": "",
        "normalisation_status": "",
        "protocol": "",
        "suspicious_patterns": [],
        "length_score": "",
        "domain_name": "",
        "long_subdomain_chain": False,
        "subdomain_count": 0,
        "suspicious_chars_obfus": [],
        "path_redirection": False,
        "misleading_brand_terms": [],
        "blacklist_result": {},
        "domain_info": {},
        "dns_records": {},
        "infrastructure": {},
        "analysis_penalties": None,
        "final_score": 0,
        "error": None,

    }

    if request.method == "POST":
        raw_url = request.form.get("url", "").strip()
        context["url"] = raw_url
        cleaned_url = URL_in(raw_url)
        context["format_status"] = "Valid URL format" if cleaned_url else "Invalid URL format"
        blacklist_hits = 0
        reputation_risk = 0

        if not cleaned_url:
            return render_template("index.html", **context)

        is_valid = val_url(cleaned_url)
        context["validation_status"] = "Valid URL" if is_valid else "Invalid URL"

        if not is_valid:
            return render_template("index.html", **context)
        
        normalised_url = normalise_url(cleaned_url)
        context["normalisation_status"] = (
            "URL normalised successfully" if normalised_url else "URL cannot be normalised"
        )

        if not normalised_url:
            return render_template("index.html", **context)

        context["url"] = normalised_url

        components = decompose_url(normalised_url)
        context["protocol"] = components.get("scheme", "")
        context["domain_name"] = components.get("domain", "")

        patt = url_pattern_analysis(normalised_url)
        context["suspicious_patterns"] = patt.get("suspicious_keywords", [])
        context["length_score"] = "Long URL" if patt.get("url_length", 0) > 120 else "Normal"

        obfus = detect_obfuscation(normalised_url)
        context["long_subdomain_chain"] = obfus.get("long_subdomain_chain", False)
        context["subdomain_count"] = obfus.get("subdomain_count", 0)
        context["suspicious_chars_obfus"] = obfus.get("suspicious_chars", [])
        context["path_redirection"] = obfus.get("path_redirection", False)
        context["misleading_brand_terms"] = obfus.get("misleading_brand_terms", [])

        blacklist = check_url_against_public_blacklists(normalised_url)
        context["blacklist_result"] = blacklist

        reputation_risk = blacklist.get("overall_blacklist_score", 0)
        blacklist_hits = 1 if reputation_risk > 0 else 0

        try:
            domain = context["domain_name"]
            if domain:
                domain_results = run_full_analysis(domain)
                context["domain_info"] = domain_results.get("domain_info", {})
                context["dns_records"] = domain_results.get("dns_records", {})
                context["infrastructure"] = domain_results.get("infrastructure", {})
                context["analysis_penalties"] = domain_results.get("analysis_penalties")
        except Exception as e:
            context["error"] = f"Domain analysis error: {str(e)}"

        context["final_score"] = score_url(
        protocol=context["protocol"],
        long_subdomain_chain=context["long_subdomain_chain"],
        subdomain_count=context["subdomain_count"],
        suspicious_chars=context["suspicious_chars_obfus"],
        path_redirection=context["path_redirection"],
        reputation_risk=reputation_risk,
        blacklist_hits=blacklist_hits,
        misleading_brand_terms=context["misleading_brand_terms"],
        domain_penalties=context["analysis_penalties"]
    )

    score = context["final_score"]

    if score >= 60:
        context["risk_level"] = "safe"
        context["risk_message"] = "This website appears safe."
    elif score >= 40:
        context["risk_level"] = "caution"
        context["risk_message"] = "This website shows suspicious indicators. Continue with caution."
    else:
        context["risk_level"] = "malicious"
        context["risk_message"] = "This website is likely malicious. Avoid using it."

    context["findings"] = findings(
        protocol=context["protocol"],
        long_subdomain_chain=context["long_subdomain_chain"],
        subdomain_count=context["subdomain_count"],
        suspicious_chars=context["suspicious_chars_obfus"],
        path_redirection=context["path_redirection"],
        blacklist_hits=blacklist_hits,
        misleading_brand_terms=context["misleading_brand_terms"],
        domain_penalties=context["analysis_penalties"]
    )

    return render_template("index.html", **context)


if __name__ == "__main__":
    print("FILE LOADED SUCCESSFULLY")
    app.run(debug=True)
