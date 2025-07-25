from ioc.regex_parser import extract_iocs_from_text
from ioc.schema import IOC

def test_extract_all_ioc_types():
    text = """
    Contact IP 192.168.1.1 or resolve at somedomain.org.
    Visit http://evil.com/path for more info.
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """
    iocs = extract_iocs_from_text(text)
    types = set(ioc.type for ioc in iocs)
    values = set(ioc.value for ioc in iocs)
    assert 'ip' in types
    assert 'domain' in types
    assert 'url' in types
    assert 'hash' in types
    assert '192.168.1.1' in values
    assert 'somedomain.org' in values
    assert any('evil.com' in val for val in values)
    assert any(len(val) == 64 for val in values)  # SHA256 length

def test_no_false_positives():
    text = "This has no IOCs, just some text."
    iocs = extract_iocs_from_text(text)
    assert iocs == []

def test_overlap_detection():
    text = "http://test.com and test.com in one line."
    iocs = extract_iocs_from_text(text)
    domains = [ioc.value for ioc in iocs if ioc.type == 'domain']
    urls = [ioc.value for ioc in iocs if ioc.type == 'url']
    assert 'test.com' in domains
    assert any('test.com' in url for url in urls)

def test_edge_case_ip():
    text = "0.0.0.0 and 255.255.255.255 should both count"
    iocs = extract_iocs_from_text(text)
    ips = [ioc.value for ioc in iocs if ioc.type == 'ip']
    assert '0.0.0.0' in ips
    assert '255.255.255.255' in ips
