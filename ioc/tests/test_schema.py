import pytest
from ioc.schema import IOC
import pydantic

def test_ip_valid():
    ioc = IOC(type='ip', value='8.8.8.8')
    assert ioc.type == 'ip'

def test_ip_invalid():
    with pytest.raises(pydantic.ValidationError):
        IOC(type='ip', value='999.999.999.999')

def test_url_valid():
    ioc = IOC(type='url', value='https://example.com')
    assert ioc.value.startswith('https://')

def test_url_invalid():
    with pytest.raises(pydantic.ValidationError):
        IOC(type='url', value='ftp://example.com')

def test_domain_valid():
    ioc = IOC(type='domain', value='example.com')
    assert ioc.type == 'domain'

def test_hash_valid():
    ioc = IOC(type='hash', value='0123456789abcdef0123456789abcdef')
    assert ioc.type == 'hash'

def test_optional_fields():
    ioc = IOC(type='ip', value='1.1.1.1', description="Test IP", source="UnitTest")
    assert ioc.description == "Test IP"
    assert ioc.source == "UnitTest"
