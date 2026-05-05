import requests
import base64
import socket
from urllib.parse import urlparse
import os

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
    except:
        return None


def check_url_against_public_blacklists(url):
    results = {
        "score": 0,
        "risk": "low",
        "notes": []
    }

    domain = get_domain(url)
    ip = get_ip(domain)

    # VirusTotal check
    if VIRUSTOTAL_API_KEY:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            resp = requests.get(endpoint, headers=headers)

            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                results["score"] += 50
                results["notes"].append(f"VirusTotal: {malicious} malicious detections")

            elif suspicious > 0:
                results["score"] += 20
                results["notes"].append(f"VirusTotal: {suspicious} suspicious detections")

        except Exception:
            results["notes"].append("VirusTotal check failed")

    # AbuseIPDB check
    if ip and ABUSEIPDB_API_KEY:
        try:
            url = "https://api.abuseipdb.com/api/v2/check"

            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }

            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }

            resp = requests.get(url, headers=headers, params=params)
            data = resp.json().get("data", {})

            score = data.get("abuseConfidenceScore", 0)

            if score >= 50:
                results["score"] += 30
                results["notes"].append(f"AbuseIPDB: high abuse score ({score})")

        except Exception:
            results["notes"].append("AbuseIPDB check failed")

    # urlscan check
    if URLSCAN_API_KEY:
        try:
            submit_url = "https://urlscan.io/api/v1/scan/"
            headers = {
                "API-Key": URLSCAN_API_KEY,
                "Content-Type": "application/json"
            }

            payload = {
                "url": url,
                "visibility": "private"
            }

            submit_resp = requests.post(submit_url, json=payload, headers=headers)
            scan_id = submit_resp.json().get("uuid")

            if scan_id:
                result_url = f"https://urlscan.io/api/v1/result/{scan_id}"
                result_resp = requests.get(result_url, headers=headers)

                data = result_resp.json()
                verdict = data.get("verdicts", {}).get("overall", {})

                if verdict.get("malicious"):
                    results["score"] += 50
                    results["notes"].append("urlscan flagged as malicious")

        except Exception:
            results["notes"].append("urlscan check failed")

    #risk level
    if results["score"] >= 60:
        results["risk"] = "high"
    elif results["score"] >= 40:
        results["risk"] = "medium"
    elif results["score"] <= 40:
        results["risk"] = "low"



    if not results["notes"]:
        results["notes"].append("No major blacklist hits")

    return results


if __name__ == "__main__":
    test = "http://example.com/login"
    print(check_url_against_public_blacklists(test))