"""Internal local inference; returned text is untrusted and grants no authority."""

import json

import httpx


_GENERATE_URL = "http://127.0.0.1:11434/api/generate"
_MODEL = "qwen3:4b-instruct"
MAX_PROMPT_CHARS = 2_000
MAX_BODY_BYTES = 65_536
MAX_OUTPUT_BYTES = 8_192


class OllamaClientError(Exception):
    """Sanitized inference failure suitable for reporting without payload data."""


class OllamaClient:
    """Use only the fixed local model; transport injection is for trusted tests."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None):
        self._transport = transport

    def generate(self, prompt: str) -> str:
        """Return bounded untrusted text, never executable instructions or authority."""
        if (
            not isinstance(prompt, str)
            or not prompt.strip()
            or len(prompt) > MAX_PROMPT_CHARS
        ):
            raise ValueError("Prompt must be a nonempty string of at most 2000 characters.")

        # Reject invalid Unicode locally without exposing it through encoder errors.
        try:
            prompt.encode("utf-8")
        except UnicodeError:
            raise ValueError("Prompt must contain valid UTF-8 text.") from None

        try:
            with httpx.Client(
                transport=self._transport,
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(connect=3.0, read=60.0, write=5.0, pool=3.0),
                headers={"Accept-Encoding": "identity"},
            ) as client:
                with client.stream(
                    "POST",
                    _GENERATE_URL,
                    json={
                        "model": _MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "think": False,
                        "options": {"num_predict": 128},
                    },
                ) as response:
                    if response.status_code != 200:
                        raise OllamaClientError("Ollama returned an unsuccessful HTTP status.")
                    # Reject compression rather than risk unbounded decompression.
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise OllamaClientError("Ollama returned an invalid response.")
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=4096):
                        if len(body) + len(chunk) > MAX_BODY_BYTES:
                            raise OllamaClientError("Ollama response exceeds the size limit.")
                        body.extend(chunk)
        except httpx.TimeoutException:
            raise OllamaClientError("Ollama request timed out.") from None
        except httpx.ConnectError:
            raise OllamaClientError("Unable to connect to local Ollama.") from None
        except httpx.RequestError:
            raise OllamaClientError("Ollama request failed.") from None

        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError):
            raise OllamaClientError("Ollama returned malformed JSON.") from None

        if not isinstance(payload, dict) or payload.get("done") is not True:
            raise OllamaClientError("Ollama returned an invalid response.")
        if payload.get("done_reason") != "stop":
            raise OllamaClientError("Ollama returned an invalid completion.")
        output = payload.get("response")
        if not isinstance(output, str) or not output.strip():
            raise OllamaClientError("Ollama returned an invalid response.")
        try:
            output_size = len(output.encode("utf-8"))
        except UnicodeError:
            raise OllamaClientError("Ollama returned an invalid response.") from None
        if output_size > MAX_OUTPUT_BYTES:
            raise OllamaClientError("Ollama output exceeds the size limit.")
        return output
