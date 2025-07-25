import pytest
from ioc.extract_api import extract_iocs_via_api
from ioc.schema import IOC

import requests
from unittest.mock import patch

def mock_api_success(*args, **kwargs):
    class MockResponse:
        def raise_for_status(self): pass
        def json(self):
            return {
                'iocs': [
                    {'type': 'ip', 'value': '1.2.3.4', 'description': 'test ip'},
                    {'type': 'domain', 'value': 'malware.org', 'description': None}
                ]
            }
    return MockResponse()

def mock_api_error(*args, **kwargs):
    class MockResponse:
        def raise_for_status(self): raise requests.HTTPError("API error")
    return MockResponse()

@patch('ioc.extract_api.requests.post', side_effect=mock_api_success)
def test_extract_iocs_via_api_success(mock_post):
    text = "malicious traffic from 1.2.3.4 malware.org"
    iocs = extract_iocs_via_api(text)
    assert any(ioc.type == 'ip' and ioc.value == '1.2.3.4' for ioc in iocs)
    assert any(ioc.type == 'domain' and ioc.value == 'malware.org' for ioc in iocs)
    assert all(isinstance(ioc, IOC) for ioc in iocs)

@patch('ioc.extract_api.requests.post', side_effect=mock_api_error)
def test_extract_iocs_via_api_failure(mock_post):
    with pytest.raises(requests.HTTPError):
        extract_iocs_via_api("test input")

def test_empty_api_response(monkeypatch):
    def mock_empty(*args, **kwargs):
        class MockResponse:
            def raise_for_status(self): pass
            def json(self): return {'iocs': []}
        return MockResponse()
    monkeypatch.setattr('ioc.extract_api.requests.post', mock_empty)
    result = extract_iocs_via_api("no iocs here")
    assert result == []
    
def test_api_key_not_set(monkeypatch):
    monkeypatch.setattr('ioc.extract_api.API_KEY', None)
    with pytest.raises(Exception):
        extract_iocs_via_api("test input")
    