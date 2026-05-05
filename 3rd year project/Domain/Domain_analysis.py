import whois as pwhois
import dns.resolver
import dns.reversename
import socket
import ssl
from datetime import datetime
import json

# ===== DOMAIN ANALYSIS FUNCTIONS =====

def calculate_age_penalty(age_years):
    """Compute the age-based penalty for the 100-point analysis score."""
    if age_years == "Unknown":
        return 0
    return 4 if age_years <= 2 else 0


def calculate_expiration_penalty(expiration_date):
    """Compute the expiration-based penalty for the 100-point analysis score."""
    if not expiration_date:
        return 0

    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    try:
        now = datetime.now()
        if hasattr(expiration_date, 'tzinfo') and expiration_date.tzinfo is not None:
            now = datetime.now(expiration_date.tzinfo)

        remaining_days = (expiration_date - now).days
        remaining_years = remaining_days / 365
        return 2 if remaining_years <= 1 else 0
    except Exception:
        return 0


def calculate_registrar_penalty(registrar):
    """Compute the registrar-based penalty for the 100-point analysis score."""
    if not registrar:
        return 0

    scam_registrars = {
        "namecheap",
        "namesilo",
        "godaddy",
        "pdr ltd",
    }

    normalized = str(registrar).strip().lower()
    return 4 if any(scam in normalized for scam in scam_registrars) else 0


def calculate_ssl_penalty(ssl_error):
    """Compute the SSL certificate penalty for the 100-point analysis score."""
    return 2 if ssl_error else 0


def get_domain_info(domain):
    """Get basic WHOIS domain information"""
    try:
        w = pwhois.whois(domain)

        # Extract key info
        domain_name = w.domain_name
        registrar = w.registrar
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        owner = w.name

        # Handle cases where creation_date is a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Calculate domain age
        if creation_date:
            now = datetime.now()
            if creation_date.tzinfo is not None:
                now = datetime.now(creation_date.tzinfo)
            age_days = (now - creation_date).days
            age_years = age_days // 365
        else:
            age_years = "Unknown"

        # Handle expiration_date if it's a list
        if isinstance(expiration_date, list) and expiration_date:
            expiration_date = expiration_date[0]

        return {
            "domain_name": domain_name,
            "registrar": registrar,
            "owner": owner,
            "creation_date": str(creation_date) if creation_date else "Unknown",
            "expiration_date": str(expiration_date) if expiration_date else "Unknown",
            "age_years": age_years,
        }

    except Exception as e:
        return None


def get_dns_records(domain):
    """Analyze DNS records (A, MX, NS, TXT)"""
    dns_data = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": []
    }
    
    try:
        # A Records (IPv4)
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            dns_data["a_records"] = [str(rdata) for rdata in a_records]
        except:
            pass
        
        # AAAA Records (IPv6)
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            dns_data["aaaa_records"] = [str(rdata) for rdata in aaaa_records]
        except:
            pass
        
        # MX Records (Mail Servers)
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            dns_data["mx_records"] = [f"Priority {rdata.preference}: {rdata.exchange}" for rdata in sorted(mx_records, key=lambda r: r.preference)]
        except:
            pass
        
        # NS Records (Nameservers)
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            dns_data["ns_records"] = [str(rdata) for rdata in ns_records]
        except:
            pass
        
        # TXT Records (SPF, DKIM, DMARC)
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for rdata in txt_records:
                for txt_string in rdata.strings:
                    dns_data["txt_records"].append(txt_string.decode())
        except:
            pass
    
    except Exception as e:
        pass
    
    return dns_data


def get_infrastructure_info(domain):
    """Analyze infrastructure: IP, SSL, nameservers"""
    infra_data = {
        "ip_address": None,
        "reverse_dns": None,
        "ssl_subject": None,
        "ssl_issuer": None,
        "ssl_not_before": None,
        "ssl_not_after": None,
        "ssl_sans": [],
        "ssl_error": None,
        "nameservers": []
    }
    
    try:
        # Get IP Address
        try:
            ip = socket.gethostbyname(domain)
            infra_data["ip_address"] = ip
            
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)
                infra_data["reverse_dns"] = hostname[0]
            except:
                pass
        except:
            pass
        
        # SSL Certificate Info
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        infra_data["ssl_subject"] = str(subject)
                        infra_data["ssl_issuer"] = str(issuer)
                        infra_data["ssl_not_before"] = cert.get('notBefore', 'N/A')
                        infra_data["ssl_not_after"] = cert.get('notAfter', 'N/A')
                        
                        sans = cert.get('subjectAltName', [])
                        if sans:
                            infra_data["ssl_sans"] = [name[1] for name in sans]
        except socket.timeout:
            infra_data["ssl_error"] = "SSL Connection timeout"
        except Exception as e:
            infra_data["ssl_error"] = str(e)
        
        # Nameserver Details
        try:
            whois_data = pwhois.whois(domain)
            if hasattr(whois_data, 'name_servers') and whois_data.name_servers:
                for ns in whois_data.name_servers:
                    ns_info = {"name": ns}
                    try:
                        ns_ip = socket.gethostbyname(ns.lower())
                        ns_info["ip"] = ns_ip
                    except:
                        pass
                    infra_data["nameservers"].append(ns_info)
        except:
            pass
    
    except Exception as e:
        pass
    
    return infra_data


def calculate_final_score(penalties):
    base_score = 100
    total_penalty = penalties.get("total_penalty", 0)
    return max(base_score - total_penalty, 0)  # Ensure score decreases and does not exceed 100

def run_full_analysis(domain):
    """Run complete analysis: WHOIS, DNS, and Infrastructure"""
    domain_info = get_domain_info(domain)
    dns_records = get_dns_records(domain)
    infrastructure = get_infrastructure_info(domain)
    analysis_penalties = None
    final_score = None

    if domain_info:
        age_penalty = calculate_age_penalty(domain_info["age_years"])
        expiration_penalty = calculate_expiration_penalty(domain_info["expiration_date"])
        registrar_penalty = calculate_registrar_penalty(domain_info["registrar"])
        ssl_penalty = calculate_ssl_penalty(infrastructure.get("ssl_error"))
        analysis_penalties = {
            "age_penalty": age_penalty,
            "expiration_penalty": expiration_penalty,
            "registrar_penalty": registrar_penalty,
            "ssl_penalty": ssl_penalty,
            "total_penalty": age_penalty + expiration_penalty + registrar_penalty + ssl_penalty
        }
        final_score = calculate_final_score(analysis_penalties)

    return {
        "domain_info": domain_info,
        "dns_records": dns_records,
        "infrastructure": infrastructure,
        "analysis_penalties": analysis_penalties,
        "final_score": final_score
    }




# Function to calculate DNS & Infrastructure penalties
def calculate_dns_infra_penalty(bad_asn_hosting, dns_instability, geo_mismatch):
    penalty = 0

    # Bad ASN / Hosting
    if bad_asn_hosting == "malicious_infra":
        penalty -= 10
    elif bad_asn_hosting == "cheap_shared_hosting":
        penalty -= 4

    # DNS Instability
    if dns_instability == "rapid_changes":
        penalty -= 5
    elif dns_instability == "moderate_changes":
        penalty -= 2

    # Geo Mismatch
    if geo_mismatch:
        penalty -= 5

    return penalty

# Function to calculate Domain & Certificate penalties
def calculate_domain_cert_penalty(domain_age, suspicious_name, tls_issues, registrar_risk):
    penalty = 0

    # Domain Age
    if domain_age < 7:
        penalty -= 15
    elif 7 <= domain_age <= 30:
        penalty -= 10
    elif 31 <= domain_age <= 180:
        penalty -= 5

    # Suspicious Domain Name
    if suspicious_name == "typosquatting_homoglyphs":
        penalty -= 5
    elif suspicious_name == "random_string":
        penalty -= 4
    elif suspicious_name == "slightly_suspicious":
        penalty -= 2

    # TLS Issues
    if tls_issues == "no_https":
        penalty -= 7
    elif tls_issues == "self_signed":
        penalty -= 5
    elif tls_issues == "weak_short_cert":
        penalty -= 3

    # Registrar Risk
    if registrar_risk == "high_risk":
        penalty -= 6
    elif registrar_risk == "moderate_risk":
        penalty -= 3

    return penalty

# Example usage (commented out to avoid interference with Flask app)
# if __name__ == "__main__":
#     # Example inputs
#     bad_asn_hosting = "malicious_infra"  # Options: "malicious_infra", "cheap_shared_hosting", None
#     dns_instability = "rapid_changes"   # Options: "rapid_changes", "moderate_changes", None
#     geo_mismatch = True                  # Options: True, False

#     total_penalty = calculate_dns_infra_penalty(bad_asn_hosting, dns_instability, geo_mismatch)
#     print(f"Total Penalty: {total_penalty}")

#     # Example inputs for Domain & Certificate
#     domain_age = 5  # Age in days
#     suspicious_name = "typosquatting_homoglyphs"  # Options: "typosquatting_homoglyphs", "random_string", "slightly_suspicious", None
#     tls_issues = "no_https"  # Options: "no_https", "self_signed", "weak_short_cert", None
#     registrar_risk = "high_risk"  # Options: "high_risk", "moderate_risk", None

#     total_penalty = calculate_domain_cert_penalty(domain_age, suspicious_name, tls_issues, registrar_risk)
#     print(f"Total Penalty: {total_penalty}")

