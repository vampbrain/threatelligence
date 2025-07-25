from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from ioc.regex_parser import extract_iocs_from_text
from ioc.extract_api import extract_iocs_via_api
from summarizer.openrouter_client import OpenRouterClient
import os
from dotenv import load_dotenv
load_dotenv()
# Single router instance for all endpoints in this file
router = APIRouter(prefix="/api", tags=["Threat Intelligence"])

# --- IOC extraction ---

class TextInput(BaseModel):
    text: str

@router.post("/extract-iocs", summary="Extract IOCs from text")
def extract_iocs(input: TextInput, method: str = "auto") -> List[dict]:
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

# --- Summarization endpoint ---

class SummarizeRequest(BaseModel):
    content: str
    mode: str = "soc"

# Load API key from env; raise if missing
api_key = os.environ.get("OPENROUTER_API_KEY")
if not api_key:
    raise RuntimeError("OPENROUTER_API_KEY environment variable is missing")

# Assuming you have a Summarizer class that uses the client
from summarizer.summarize import Summarizer
summarizer = Summarizer(api_key=api_key, model="mistralai/mistral-7b-instruct:free")

@router.post("/summarize", summary="Summarize threat intel content")
def summarize(request: SummarizeRequest):
    try:
        summary_text = summarizer.summarize(request.content, request.mode)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Summarization error: {str(e)}")
    return {"summary": summary_text}
