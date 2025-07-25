import pytest
from unittest.mock import patch
from ioc.enrichment import enrich_ip_abusedb, enrich_virustotal, enrich_ioc
from ioc.schema import IOC

# Sample mock data for AbuseIPDB response
MOCK_ABUSEIPDB_RESPONSE = {
    "abuse_confidence": 80,
    "total_reports": 12,
    "country": "US",
    "usage_type": "Data Center/Web Hosting/Transit",
    "isp": "Google LLC",
    "domain": "google.com",
    "last_reported": "2025-07-20T12:00:00Z"
}

# Sample mock data for VirusTotal response
MOCK_VT_RESPONSE = {
    "malicious": 7,
    "suspicious": 1,
    "undetected": 34,
    "harmless": 10,
    "last_analysis_date": 1658900000,
    "first_submission_date": 1658000000,
    "categories": {"category1": "example"},
    "total_votes": {"harmless": 5, "malicious": 2}
}

# === Unit test for AbuseIPDB enrichment with mock ===
@patch('ioc.enrichment.requests.get')
def test_enrich_ip_abuseipdb_mock(mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "data": {
            "abuseConfidenceScore": MOCK_ABUSEIPDB_RESPONSE['abuse_confidence'],
            "totalReports": MOCK_ABUSEIPDB_RESPONSE['total_reports'],
            "countryCode": MOCK_ABUSEIPDB_RESPONSE['country'],
            "usageType": MOCK_ABUSEIPDB_RESPONSE['usage_type'],
            "isp": MOCK_ABUSEIPDB_RESPONSE['isp'],
            "domain": MOCK_ABUSEIPDB_RESPONSE['domain'],
            "lastReportAt": MOCK_ABUSEIPDB_RESPONSE['last_reported'],
        }
    }

    result = enrich_ip_abusedb("8.8.8.8")
    assert result["abuse_confidence"] == 80
    assert result["total_reports"] == 12
    assert result["country"] == "US"
    assert result["isp"] == "Google LLC"

# === Unit test for VirusTotal enrichment with mock ===
@patch('ioc.enrichment.requests.get')
def test_enrich_virustotal_mock(mock_get):
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": MOCK_VT_RESPONSE['malicious'],
                    "suspicious": MOCK_VT_RESPONSE['suspicious'],
                    "undetected": MOCK_VT_RESPONSE['undetected'],
                    "harmless": MOCK_VT_RESPONSE['harmless'],
                },
                "last_analysis_date": MOCK_VT_RESPONSE['last_analysis_date'],
                "first_submission_date": MOCK_VT_RESPONSE['first_submission_date'],
                "categories": MOCK_VT_RESPONSE['categories'],
                "total_votes": MOCK_VT_RESPONSE['total_votes'],
            }
        }
    }

    ioc = IOC(type="ip", value="8.8.8.8")
    result = enrich_virustotal(ioc.type, ioc.value)
    assert result["malicious"] == 7
    assert result["suspicious"] == 1
    assert result["undetected"] == 34
    assert result["harmless"] == 10

# === Unit test for full enrichment pipeline with mocked external calls ===
@patch('ioc.enrichment.enrich_ip_abusedb')
@patch('ioc.enrichment.enrich_virustotal')
def test_enrich_ioc_pipeline_mock(mock_vt, mock_abuse):
    mock_abuse.return_value = MOCK_ABUSEIPDB_RESPONSE
    mock_vt.return_value = MOCK_VT_RESPONSE

    ioc = IOC(type="ip", value="8.8.8.8")
    enriched = enrich_ioc(ioc, source_confidence=0.95, sightings=3, first_seen="2025-07-01T00:00:00")

    assert enriched.enrichment['abuseipdb']['abuse_confidence'] == 80
    assert enriched.enrichment['virustotal']['malicious'] == 7
    assert 0 <= enriched.risk_score <= 100
    assert enriched.base_score <= 10
    assert enriched.sightings == 3