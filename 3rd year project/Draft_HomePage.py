from urllib.parse import urlparse
from flask import Flask, render_template, request
from URL.URL_in import URL_in
from URL.URL_val import val_url
from URL.URL_norm import normalise_url
from URL.URL_decom import decompose_url
from URL.URL_patt import url_pattern_analysis
from URL.URL_detect_obfus import detect_obfuscation
from BlackList.Global_blacklist import check_url_against_public_blacklists
from Domain.Domain_analysis import run_full_analysis
from Scoring.Scoring import score_url
from Findings.Findings import findings

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    data = {
        "url": "",
        "final_score": 0,
        "risk_level": "",
        "risk_message": "",
        "error": None,
    }

    if request.method == "POST":

        raw_url = request.form.get("url", "").strip()
        data["url"] = raw_url

        cleaned_url = URL_in(raw_url)

        if not cleaned_url:
            data["format_status"] = "Invalid URL format"
            return render_template("index.html", **data)

        data["format_status"] = "Valid URL format"
        if not val_url(cleaned_url):
            data["validation_status"] = "Invalid URL"
            return render_template("index.html", **data)

        data["validation_status"] = "Valid URL"
        normalised_url = normalise_url(cleaned_url)

        if not normalised_url:
            data["normalisation_status"] = "URL could not be normalised"
            return render_template("index.html", **data)

        data["normalisation_status"] = "URL normalised successfully"
        data["url"] = normalised_url

        parsed_url = urlparse(normalised_url)

        #URL
        components = decompose_url(normalised_url)

        data["protocol"] = components.get("scheme")
        data["domain_name"] = components.get("domain")

      #Pattern analysis
        pattern_info = url_pattern_analysis(normalised_url)

        data["suspicious_patterns"] = pattern_info.get(
            "suspicious_keywords", [])

        url_length = pattern_info.get("url_length", 0)
        data["length_score"] = "Long URL" if url_length > 120 else "Normal"

        #Obfuscation checks
        obfuscation = detect_obfuscation(normalised_url)

        data["long_subdomain_chain"] = obfuscation.get(
            "long_subdomain_chain", False)

        data["subdomain_count"] = obfuscation.get(
            "subdomain_count", 0)

        data["suspicious_chars_obfus"] = obfuscation.get(
            "suspicious_chars", [])

        data["path_redirection"] = obfuscation.get(
            "path_redirection", False)

        data["misleading_brand_terms"] = obfuscation.get(
            "misleading_brand_terms", []
        )

        #Blacklist checks
        blacklist_result = check_url_against_public_blacklists(
            normalised_url)

        data["blacklist_result"] = blacklist_result

        reputation_risk = blacklist_result.get("score", 0)


        blacklist_hits = 1 if reputation_risk >= 40 else 0


        #Domain analysis
        domain = parsed_url.netloc.lower()

        if domain:
            try:
                domain_results = run_full_analysis(domain)

                data["domain_info"] = domain_results.get(
                    "domain_info", {})

                data["dns_records"] = domain_results.get(
                    "dns_records", {} )

                data["infrastructure"] = domain_results.get(
                    "infrastructure", {})

                data["analysis_penalties"] = domain_results.get(
                    "analysis_penalties", {})

            except Exception as e:
                print("Domain analysis failed:", e)
                data["error"] = "Could not complete domain analysis"

        penalties = data.get("analysis_penalties", {})
        print("HOSTING PENALTY:", penalties.get("hosting_penalty"))

        score = score_url(
            protocol=data.get("protocol"),
            long_subdomain_chain=data.get(
                "long_subdomain_chain"),
            subdomain_count=data.get("subdomain_count"),
            suspicious_chars=data.get(
                "suspicious_chars_obfus"),
            path_redirection=data.get("path_redirection"),
            reputation_risk=reputation_risk,
            blacklist_hits=blacklist_hits,
            misleading_brand_terms=data.get(
                "misleading_brand_terms"),
            domain_penalties=penalties,
        )

        data["final_score"] = score

        #Risk level
        if score >= 85:
            data["risk_level"] = "safe"
            data["risk_message"] = "This website appears safe."

        elif score >= 50:
            data["risk_level"] = "caution"
            data["risk_message"] = (
                "This website contains suspicious indicators.")
        else:
            data["risk_level"] = "malicious"
            data["risk_message"] = (
                "This website is likely malicious.")
            
        print("DEBUG protocol:", data.get("protocol"))
        print("DEBUG suspicious_chars:", data.get("suspicious_chars_obfus"))
        print("DEBUG path_redirection:", data.get("path_redirection"))
        print("DEBUG blacklist_hits:", blacklist_hits)
        print("DEBUG misleading_brand_terms:", data.get("misleading_brand_terms"))
        print("DEBUG domain_penalties:", penalties)

        data["findings"] = findings(
            protocol=data.get("protocol"),
            long_subdomain_chain=data.get(
                "long_subdomain_chain"),
            subdomain_count=data.get("subdomain_count"),
            suspicious_chars=data.get(
                "suspicious_chars_obfus"),
            path_redirection=data.get("path_redirection"),
            blacklist_hits=blacklist_hits,
            misleading_brand_terms=data.get(
                "misleading_brand_terms"),
            domain_penalties=penalties,
        )

    return render_template("index.html", **data)


if __name__ == "__main__":
    app.run(debug=True)