import re
from typing import List
from ioc.schema import IOC

# Example regexes; refine as needed
IP_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
DOMAIN_REGEX = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b'
URL_REGEX = r'https?://[^\s/$.?#].[^\s]*'
HASH_REGEX = r'\b[a-fA-F0-9]{32,64}\b'  # MD5, SHA1, SHA256 length hashes

def extract_iocs_from_text(text: str) -> List[IOC]:
    iocs = []

    for ip in re.findall(IP_REGEX, text):
        iocs.append(IOC(type='ip', value=ip))

    for domain in re.findall(DOMAIN_REGEX, text):
        iocs.append(IOC(type='domain', value=domain))

    for url in re.findall(URL_REGEX, text):
        iocs.append(IOC(type='url', value=url))

    for h in re.findall(HASH_REGEX, text):
        iocs.append(IOC(type='hash', value=h))

    return iocs
