import pytest
from ioc.enrichment import enrich_ioc
from ioc.schema import IOC

@pytest.mark.skip(reason="Integration test hitting real APIs")
def test_enrich_ioc_real_api():
    ioc = IOC(type="ip", value="8.8.8.8")
    enriched = enrich_ioc(ioc)
    assert enriched.ioc_value == "8.8.8.8"
    # We expect some results, even if minimal
    assert 'abuseipdb' in enriched.enrichment
    assert 'virustotal' in enriched.enrichment
