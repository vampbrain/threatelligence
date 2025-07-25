import requests
from typing import List
from ioc.schema import IOC

API_URL = "https://api.iocparser.com/extract"
API_KEY = "your_api_key_here"  # Add config management

def extract_iocs_via_api(text: str) -> List[IOC]:
    headers = {'Authorization': f'Bearer {API_KEY}', 'Content-Type': 'application/json'}
    payload = {"text": text}
    response = requests.post(API_URL, json=payload, headers=headers, timeout=10)

    response.raise_for_status()
    data = response.json()

    iocs = []
    for item in data.get('iocs', []):
        iocs.append(IOC(
            type=item['type'],
            value=item['value'],
            description=item.get('description'),
            source='iocparser_api'
        ))
    return iocs
