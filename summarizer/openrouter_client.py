import requests
import logging
from typing import Optional, Dict

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class OpenRouterClient:
    def __init__(
        self,
        api_key: str,
        model: str = "mistralai/mistral-7b-instruct:free",
        endpoint: str = "https://openrouter.ai/api/v1/chat/completions",
    ):
        if not api_key:
            raise ValueError("API key must be provided for OpenRouterClient")
        self.api_key = api_key
        self.model = model
        self.endpoint = endpoint

    def summarize(
        self,
        prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.4,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }

        try:
            response = requests.post(
                self.endpoint, json=payload, headers=headers, timeout=45
            )
            response.raise_for_status()
        except requests.HTTPError as http_err:
            logger.error(f"HTTPError from OpenRouter API: {http_err} - Response: {response.text}")
            raise
        except requests.RequestException as req_err:
            logger.error(f"RequestException during OpenRouter API call: {req_err}")
            raise

        try:
            result = response.json()
        except ValueError as json_err:
            logger.error(f"Error decoding JSON from OpenRouter response: {json_err}")
            raise

        logger.debug(f"OpenRouter raw response: {result}")

        choices = result.get("choices")
        if not choices or not isinstance(choices, list):
            error_msg = "OpenRouter response missing 'choices' or 'choices' is not a list."
            logger.error(error_msg)
            raise ValueError(error_msg)

        first_choice = choices[0]
        if (
            not first_choice
            or "message" not in first_choice
            or "content" not in first_choice["message"]
        ):
            error_msg = "OpenRouter response missing expected 'message.content' field."
            logger.error(error_msg)
            raise ValueError(error_msg)

        content = first_choice["message"]["content"]
        if content is None:
            error_msg = "OpenRouter response 'message.content' is None."
            logger.error(error_msg)
            raise ValueError(error_msg)

        return content.strip()
