import requests
from typing import List, Optional, Dict, Any
from functools import lru_cache
from ioc.schema import IOC, IOCEnrichment
import datetime as dt
import os

#apis
abuse = os.environ.get('abusedb')
vt = os.environ.get('vtapi')

def cache(maxsize = 128):
    return lru_cache(maxsize=maxsize)

@cache(maxsize = 256)
def enrich_ip_abusedb(ip:str) -> Dict[str, Any]:
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        "Accept": "application/json",
        "Key": abuse
    }
    
    params = {"ipAddress": ip, "maxAgeInDays":90}
    response = requests.get(url, headers=headers, params=params)
    
    response.raise_for_status()
    data = response.json().get("data", {})
    
    return {
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "total_reports" : data.get("totalReports", 0),
        "country": data.get("countryCode"),
        "usage_type" : data.get("usageType"),
        "isp" : data.get("isp"),
        "domain": data.get("domain"),
        "last_reported": data.get("lastReportAt")
    }
    
@cache(maxsize=256)
def enrich_virustotal(ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Support enrichment for IP, domain, url, or hash via VirusTotal"""
    headers = {"x-apikey": vt}
    base_url = "https://www.virustotal.com/api/v3"
    
    vt_endpoints = {
        "ip": f"{base_url}/ip_addresses/{ioc_value}",
        "domain": f"{base_url}/domains/{ioc_value}",
        "url": f"{base_url}/urls/{ioc_value}",
        "hash": f"{base_url}/files/{ioc_value}",
    }
    url = vt_endpoints.get(ioc_type)
    if not url:
        return {}

    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    data = response.json().get("data", {})
    attributes = data.get("attributes", {})

    # Summarize analysis stats, malicious counts, etc.
    analysis_stats = attributes.get("last_analysis_stats", {})
    
    return {
        "malicious": analysis_stats.get("malicious", 0),
        "suspicious": analysis_stats.get("suspicious", 0),
        "undetected": analysis_stats.get("undetected", 0),
        "harmless": analysis_stats.get("harmless", 0),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "first_submission_date": attributes.get("first_submission_date"),
        "categories": attributes.get("categories", {}),
        "total_votes": attributes.get("total_votes", {}),
    }

# === Utility: Decay Function for Age-Based Risk Decay ===
def decay_function(age_days: int, decay_rate: int = 30) -> float:
    """Returns a decay multiplier between 0 and 1, decreasing with age"""
    return 1.0 / (1.0 + age_days / decay_rate)

# === Scoring Function ===
def compute_base_score(enrichment: Dict[str, Any], source_confidence: float, sightings: int) -> float:
    # Example: simple integer weighted score inspired by RiskSLIM
    abuse_score = enrichment.get("abuseipdb", {}).get("abuse_confidence", 0)
    vt_malicious = enrichment.get("virustotal", {}).get("malicious", 0)

    score = (
        2 * (abuse_score > 70) +
        3 * (vt_malicious > 5) +
        1 * (source_confidence > 0.8) +
        1 * (sightings > 2)
    )
    return min(score, 10)  # cap at 10 for normalization

def misp_style_risk_score(enrichment: Dict[str, Any], base_score: float,
                          first_seen: Optional[dt.date]) -> float:
    today = dt.datetime.now(dt.UTC).date()
    age_days = (today - first_seen).days if first_seen else 0
    decay = decay_function(age_days)
    risk = base_score * decay
    return round(risk * 10, 2)  # scale 0-100

# === Main Enrichment Pipeline ===
def enrich_ioc(ioc: IOC,
               source_confidence: float = 0.9,
               sightings: int = 1,
               first_seen: Optional[str] = None,
               last_seen: Optional[str] = None) -> IOCEnrichment:
    enrichment_results: Dict[str, Any] = {}

    # Call enrichers based on IOC type
    try:
        if ioc.type == "ip":
            abuse_data = enrich_ip_abusedb(ioc.value)
            enrichment_results["abuseipdb"] = abuse_data
        else:
            enrichment_results["abuseipdb"] = {}

        vt_data = enrich_virustotal(ioc.type, ioc.value)
        enrichment_results["virustotal"] = vt_data
    except requests.HTTPError as e:
        # Log error or handle gracefully
        enrichment_results["abuseipdb"] = enrichment_results.get("abuseipdb", {})
        enrichment_results["virustotal"] = enrichment_results.get("virustotal", {})

    # Convert first_seen/last_seen strings to date if provided
    fs_date = None
    if first_seen:
        try:
            fs_date = dt.datetime.fromisoformat(first_seen).date()
        except Exception:
            pass

    # Compute scoring
    base_score = compute_base_score(enrichment_results, source_confidence, sightings)
    risk_score = misp_style_risk_score(enrichment_results, base_score, fs_date)

    # Compose enrichment model instance
    enrichment_model = IOCEnrichment(
        ioc_type=ioc.type,
        ioc_value=ioc.value,
        base_score=base_score,
        enrichment=enrichment_results,
        sightings=sightings,
        first_seen=first_seen,
        last_seen=last_seen,
        source_confidence=source_confidence,
        risk_score=risk_score,
        tags=None,
    )

    return enrichment_model


# === Example: Run standalone test ===
if __name__ == "__main__":
    test_ioc = IOC(type="ip", value="8.8.8.8")
    enriched = enrich_ioc(test_ioc)
    print(enriched.model_dump_json(indent=2))