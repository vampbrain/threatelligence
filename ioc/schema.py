from pydantic import BaseModel, field_validator
from typing import Optional, Literal, List, Dict
import re
import ipaddress


class IOC(BaseModel):
    type: Literal['ip', 'domain', 'url', 'hash']
    value: str
    description: Optional[str] = None
    source: Optional[str] = None

    @field_validator('value')
    def check_value_format(cls, v, info):
        # Access the 'type' field of the model instance under validation
        t = info.data.get('type') if info.data else None

        if t == 'ip':
            # Use ipaddress for strict IPv4 validation (raises ValueError if invalid)
            try:
                ipaddress.IPv4Address(v)
            except ValueError:
                raise ValueError('Invalid IPv4 address')

        elif t == 'url':
            # Basic URL check (must start with http:// or https://)
            if not v.startswith(('http://', 'https://')):
                raise ValueError('URL must start with http:// or https://')

        elif t == 'domain':
            domain_pattern = re.compile(
                r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}$',
                re.IGNORECASE,
            )
            if not domain_pattern.match(v):
                raise ValueError('Invalid domain format')

        elif t == 'hash':
            hash_pattern = re.compile(r'^[a-fA-F0-9]{32,64}$')
            if not hash_pattern.match(v):
                raise ValueError('Invalid hash format')

        return v

class IOCEnrichment(BaseModel):
    ioc_type: Literal['ip', 'domain', 'url', 'hash']
    ioc_value: str
    base_score: float
    enrichment: Dict[str, dict]
    sightings: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    source_confidence: float
    risk_score: float
    tags: Optional[List[str]] = None
    
    
    