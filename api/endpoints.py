from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel
from typing import List
from ioc.regex_parser import extract_iocs_from_text
from ioc.extract_api import extract_iocs_via_api

router = APIRouter(prefix="/api", tags=["Threat Intelligence"])

class TextInput(BaseModel):
    text: str

@router.post("/extract-iocs", summary="Extract IOCs from text")
def extract_iocs(input: TextInput, method: str = "auto"):
    """
    Extract IOCs from raw text input using API, regex, or both.
    """
    text = input.text
    results = []

    try:
        if method == "api":
            results = extract_iocs_via_api(text)
        elif method == "regex":
            results = extract_iocs_from_text(text)
        else:  # 'auto': API first, fallback to regex
            try:
                results = extract_iocs_via_api(text)
            except Exception:
                results = extract_iocs_from_text(text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return [ioc.model_dump() for ioc in results]

# More endpoints can be added similarly for enrichment and summarization
