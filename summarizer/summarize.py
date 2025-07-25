from .openrouter_client import OpenRouterClient
from .prompts import PROMPT_MAP
from .cache import SummaryCache  
import os


from dotenv import load_dotenv
load_dotenv()
api_key = os.environ.get("OPENROUTER_API_KEY")
class Summarizer:
    def __init__(self, api_key: str, model: str = None, cache: 'SummaryCache' = None):
        self.llm = OpenRouterClient(api_key, model=model)  # allow override of LLM
        self.cache = cache

    def summarize(self, content: str, mode: str = "soc") -> str:
        prompt_template = PROMPT_MAP.get(mode, PROMPT_MAP["soc"])
        prompt = prompt_template.format(content=content.strip())
        cache_key = f"{hash(prompt)}"
        
        if self.cache:
            summary = self.cache.get(cache_key)
            if summary:
                return summary

        try:
            summary = self.llm.summarize(prompt)
        except Exception as e:
            summary = f"Summary unavailable: {str(e)}"
        
        if self.cache:
            self.cache.set(cache_key, summary)
        return summary
