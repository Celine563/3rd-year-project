import requests
import base64
import socket
from urllib.parse import urlparse
import os
import time

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")


def get_domain(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse("http://" + url)
    return parsed.netloc


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"Could not resolve IP for {domain}")
        return None


def check_url_against_public_blacklists(url):
    results = {
        "score": 0,
        "risk": "low",
        "notes": []
    }

    domain = get_domain(url)
    ip = get_ip(domain)

    # VirusTotal
    if VIRUSTOTAL_API_KEY:
        try:
            encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"

            resp = requests.get(
                vt_url,
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10
            )

            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious:
                    results["score"] += 50
                    results["notes"].append(
                        f"VirusTotal flagged {malicious} malicious detections"
                    )

                elif suspicious:
                    results["score"] += 20
                    results["notes"].append(
                        f"VirusTotal reported {suspicious} suspicious detections"
                    )

        except requests.RequestException:
            results["notes"].append("VirusTotal request failed")

    # AbuseIPDB
    if ip and ABUSEIPDB_API_KEY:
        try:
            abuse_url = "https://api.abuseipdb.com/api/v2/check"

            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }

            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }

            resp = requests.get(
                abuse_url,
                headers=headers,
                params=params,
                timeout=10
            )

            if resp.status_code == 200:
                score = resp.json().get("data", {}).get(
                    "abuseConfidenceScore", 0
                )

                if score >= 50:
                    results["score"] += 30
                    results["notes"].append(
                        f"AbuseIPDB confidence score is high ({score})"
                    )

        except requests.RequestException:
            results["notes"].append("AbuseIPDB check failed")

    # urlscan
    if URLSCAN_API_KEY:
        try:
            headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"
            }

            payload = {"url": url, "visibility": "private"}

            submit_resp = requests.post("https://urlscan.io/api/v1/scan/", 
                                        json=payload, 
                                        headers=headers)

            scan_id = submit_resp.json().get("uuid")

            if scan_id:
                time.sleep(2)

                result_url = f"https://urlscan.io/api/v1/result/{scan_id}"
                result_resp = requests.get(result_url, headers=headers)

                if result_resp.status_code == 200:
                    verdict = (result_resp.json()
                               .get("verdicts", {})
                               .get("overall", {}))

                    if verdict.get("malicious"):results["score"] += 50 
                    results["notes"].append("urlscan marked this URL as malicious")

        except Exception:
            results["notes"].append("urlscan lookup failed")

    # overall risk
    if results["score"] >= 60:
        results["risk"] = "high"
    elif results["score"] >= 40:
        results["risk"] = "medium"
    else:
        results["risk"] = "low"

    if not results["notes"]:
        results["notes"].append("No major blacklist hits")

    return results


if __name__ == "__main__":
    test_url = "http://example.com/login"
    print(check_url_against_public_blacklists(test_url))