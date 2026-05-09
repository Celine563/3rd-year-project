import whois as pwhois
import dns.resolver
import socket
import ssl

from datetime import datetime


# ===== DOMAIN ANALYSIS =====

def calculate_age_penalty(age_years):
    if age_years is None or age_years == "Unknown":
        return 0

    return 4 if age_years <= 2 else 0


def calculate_expiration_penalty(expiration_date):
    if not expiration_date or expiration_date == "Unknown":
        return 0

    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    try:
        now = datetime.now()

        if hasattr(expiration_date, "tzinfo") and expiration_date.tzinfo:
            now = datetime.now(expiration_date.tzinfo)

        remaining_days = (expiration_date - now).days
        remaining_years = remaining_days / 365

        return 2 if remaining_years <= 1 else 0

    except Exception:
        return 0


def calculate_ssl_penalty(ssl_error):
    return 2 if ssl_error else 0


SCAM_REGISTRARS = {
    "namesilo",
    "namecheap",
    "godaddy",
    "godaddy.com",
    "godaddy.com, llc",
    "wild west domains",
    "pdr ltd",
    "publicdomainregistry",
    "okayjersey",
    "okayjersey.com",
}


def calculate_registrar_penalty(registrar):
    if not registrar:
        return 0

    registrar = str(registrar).lower().strip()

    return 4 if any(name in registrar for name in SCAM_REGISTRARS) else 0


def detect_hosting_platform(domain):
    risky_hosts = [
        "godaddysites.com",
        "wixsite.com",
        "weebly.com",
        "github.io",
        "vercel.app",
    ]

    domain = domain.lower()

    return any(host in domain for host in risky_hosts)


def calculate_domain_name_penalty(domain):
    suspicious = {"okayjersey", "okayjersey.com"}

    domain = domain.lower()

    return 20 if any(name in domain for name in suspicious) else 0


def get_domain_info(domain):

    try:
        w = pwhois.whois(domain)

    except Exception:
        return {}

    creation_date = w.creation_date
    expiration_date = w.expiration_date

    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    if creation_date:
        now = (
            datetime.now(creation_date.tzinfo)
            if creation_date.tzinfo
            else datetime.now())

        age_days = (now - creation_date).days
        age_years = age_days // 365

    else:
        age_years = "Unknown"

    return {
        "domain_name": w.domain_name,
        "registrar": w.registrar,
        "owner": w.name,
        "creation_date": str(creation_date) if creation_date else "Unknown",
        "expiration_date": str(expiration_date) if expiration_date else "Unknown",
        "age_years": age_years,
    }


def get_dns_records(domain):

    dns_data = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
    }

    # A records
    try:
        a_records = dns.resolver.resolve(domain, "A")
        dns_data["a_records"] = [str(r) for r in a_records]

    except Exception:
        pass

    # AAAA records
    try:
        aaaa_records = dns.resolver.resolve(domain, "AAAA")
        dns_data["aaaa_records"] = [str(r) for r in aaaa_records]

    except Exception:
        pass

    # MX records
    try:
        mx_records = dns.resolver.resolve(domain, "MX")

        dns_data["mx_records"] = [
            f"Priority {r.preference}: {r.exchange}"
            for r in sorted(mx_records, key=lambda x: x.preference)
        ]

    except Exception:
        pass

# NS records
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        dns_data["ns_records"] = [str(r) for r in ns_records]

    except Exception:
        pass

    # TXT records
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")

        for record in txt_records:
            for txt in record.strings:
                dns_data["txt_records"].append(txt.decode())

    except Exception:
        pass

    return dns_data


def get_infrastructure_info(domain):

    infra = {
        "ip_address": None,
        "reverse_dns": None,
        "ssl_subject": None,
        "ssl_issuer": None,
        "ssl_not_before": None,
        "ssl_not_after": None,
        "ssl_sans": [],
        "ssl_error": None,
        "nameservers": [],
    }

    # IP 
    try:
        ip = socket.gethostbyname(domain)
        infra["ip_address"] = ip

        try:
            hostname = socket.gethostbyaddr(ip)
            infra["reverse_dns"] = hostname[0]

        except Exception:
            pass

    except Exception:
        pass

    #SSL info
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))

                    infra["ssl_subject"] = str(subject)
                    infra["ssl_issuer"] = str(issuer)

                    infra["ssl_not_before"] = cert.get(
                        "notBefore", "N/A")

                    infra["ssl_not_after"] = cert.get(
                        "notAfter", "N/A")

                    infra["ssl_sans"] = [
                        name[1]
                        for name in cert.get(
                            "subjectAltName", [])
                    ]

    except socket.timeout:
        infra["ssl_error"] = "SSL connection timeout"

    except Exception as e:
        infra["ssl_error"] = str(e)

    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        infra["nameservers"] = [str(r) for r in ns_records]

    except Exception:
        pass

    return infra


def calculate_final_score(penalties):
    return max(100 - penalties.get("total_penalty", 0), 0)


def run_full_analysis(domain):

    domain_info = get_domain_info(domain)
    dns_records = get_dns_records(domain)
    infrastructure = get_infrastructure_info(domain)

    age_penalty = calculate_age_penalty(
        domain_info.get("age_years"))
    expiration_penalty = calculate_expiration_penalty(
        domain_info.get("expiration_date"))

    registrar_penalty = calculate_registrar_penalty(
        domain_info.get("registrar"))

    ssl_penalty = calculate_ssl_penalty(
        infrastructure.get("ssl_error"))

    domain_name_penalty = calculate_domain_name_penalty(domain)

    penalties = {
        "age_penalty": age_penalty,
        "expiration_penalty": expiration_penalty,
        "registrar_penalty": registrar_penalty,
        "ssl_penalty": ssl_penalty,
        "domain_name_penalty": domain_name_penalty,
        "total_penalty": (age_penalty + expiration_penalty + registrar_penalty + ssl_penalty + domain_name_penalty ),
    }

    return {
        "domain_info": domain_info,
        "dns_records": dns_records,
        "infrastructure": infrastructure,
        "analysis_penalties": penalties,
        "final_score": calculate_final_score(penalties),
    }


def calculate_dns_infra_penalty(
    bad_asn_hosting,
    dns_instability,
    geo_mismatch
):

    penalty = 0

    if bad_asn_hosting == "malicious_infra":
        penalty -= 10

    elif bad_asn_hosting == "cheap_shared_hosting":
        penalty -= 4
# Bad ASN / Hosting
    if dns_instability == "rapid_changes":
        penalty -= 5
# DNS Instability
    elif dns_instability == "moderate_changes":
        penalty -= 2
# Geo Mismatch
    if geo_mismatch:
        penalty -= 5

    return penalty

# Function to calculate Domain & Certificate penalties
def calculate_domain_cert_penalty(domain_age, suspicious_name, tls_issues,registrar_risk):

    penalty = 0

    if domain_age < 7:
        penalty -= 15

    elif domain_age <= 30:
        penalty -= 10

    elif domain_age <= 180:
        penalty -= 5

    if suspicious_name == "typosquatting_homoglyphs":
        penalty -= 5

    elif suspicious_name == "random_string":
        penalty -= 4

    elif suspicious_name == "slightly_suspicious":
        penalty -= 2

    if tls_issues == "no_https":
        penalty -= 7

    elif tls_issues == "self_signed":
        penalty -= 5

    elif tls_issues == "weak_short_cert":
        penalty -= 3

    if registrar_risk == "high_risk":
        penalty -= 6

    elif registrar_risk == "moderate_risk":
        penalty -= 3

    return penalty