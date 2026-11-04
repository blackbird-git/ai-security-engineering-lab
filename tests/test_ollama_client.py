"""Mock-only inference tests: no live Ollama or real network transport."""

import json

import httpx
import pytest

from app.ollama_client import (
    MAX_BODY_BYTES,
    MAX_OUTPUT_BYTES,
    OllamaClient,
    OllamaClientError,
)


def client_for(handler):
    return OllamaClient(transport=httpx.MockTransport(handler))


def test_generation_destination_and_parameters(caplog):
    def handler(request):
        assert request.method == "POST"
        assert str(request.url) == "http://127.0.0.1:11434/api/generate"
        assert json.loads(request.content) == {
            "model": "qwen3:4b-instruct",
            "prompt": "Synthetic test prompt",
            "stream": False,
            "think": False,
            "options": {"num_predict": 128},
        }
        assert request.extensions["timeout"] == {
            "connect": 3.0, "read": 60.0, "write": 5.0, "pool": 3.0,
        }
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, json={"response": " untrusted text ", "done": True, "done_reason": "stop"})

    assert client_for(handler).generate("Synthetic test prompt") == " untrusted text "
    assert "Synthetic test prompt" not in caplog.text
    assert "untrusted text" not in caplog.text


def test_stop_completion_succeeds():
    payload = {"response": "Synthetic answer", "done": True, "done_reason": "stop"}
    assert client_for(lambda request: httpx.Response(200, json=payload)).generate("test") == "Synthetic answer"


def test_length_completion_regression(caplog):
    # Reproduce the reported completion metadata and character count, not raw model text.
    payload = {"response": "x" * 587, "done": True, "done_reason": "length"}
    with pytest.raises(OllamaClientError) as caught:
        client_for(lambda request: httpx.Response(200, json=payload)).generate("PRIVATE_PROMPT")
    assert str(caught.value) == "Ollama returned an invalid completion."
    assert payload["response"] not in caplog.text
    assert "PRIVATE_PROMPT" not in caplog.text


def test_missing_completion_reason_is_rejected():
    payload = {"response": "PRIVATE_RESPONSE", "done": True}
    with pytest.raises(OllamaClientError) as caught:
        client_for(lambda request: httpx.Response(200, json=payload)).generate("test")
    assert str(caught.value) == "Ollama returned an invalid completion."


@pytest.mark.parametrize(
    "reason", [None, True, False, 0, 1, [], {}, "", "STOP", " stop", "stop ", "load", "unload", "PRIVATE_REASON"]
)
def test_invalid_or_unexpected_completion_reason_is_sanitized(reason, caplog):
    payload = {"response": "PRIVATE_RESPONSE", "done": True, "done_reason": reason}
    with pytest.raises(OllamaClientError) as caught:
        client_for(lambda request: httpx.Response(200, json=payload)).generate("PRIVATE_PROMPT")
    assert str(caught.value) == "Ollama returned an invalid completion."
    assert "PRIVATE" not in caplog.text


@pytest.mark.parametrize("prompt", [None, 1, True, [], {}, "", " \n\t", "x" * 2001, "\ud800"])
def test_invalid_prompts_never_send(prompt):
    def handler(request):
        pytest.fail("Invalid prompt must not send a request")

    with pytest.raises(ValueError):
        client_for(handler).generate(prompt)


def test_maximum_prompt_is_accepted():
    client = client_for(lambda request: httpx.Response(200, json={"response": "ok", "done": True, "done_reason": "stop"}))
    assert client.generate("x" * 2000) == "ok"


def test_environment_and_redirect_settings(monkeypatch):
    original_client = httpx.Client
    settings = []

    def capture_client(**kwargs):
        settings.append(kwargs)
        return original_client(**kwargs)

    monkeypatch.setattr(httpx, "Client", capture_client)
    client = client_for(lambda request: httpx.Response(200, json={"response": "ok", "done": True, "done_reason": "stop"}))
    assert client.generate("test") == "ok"
    assert settings[0]["trust_env"] is False
    assert settings[0]["follow_redirects"] is False


@pytest.mark.parametrize("status", [201, 204, 301, 302, 307, 308, 400, 401, 404, 429, 500])
def test_http_errors_and_redirects_are_sanitized(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, text="PRIVATE_BODY", headers={"Location": "https://example.invalid"})

    with pytest.raises(OllamaClientError, match="unsuccessful HTTP status") as caught:
        client_for(handler).generate("PRIVATE_PROMPT")
    assert len(calls) == 1
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.parametrize(
    "error, message",
    [
        (httpx.ConnectError, "Unable to connect"),
        (httpx.ConnectTimeout, "timed out"),
        (httpx.ReadTimeout, "timed out"),
        (httpx.WriteTimeout, "timed out"),
        (httpx.PoolTimeout, "timed out"),
        (httpx.ReadError, "request failed"),
        (httpx.RemoteProtocolError, "request failed"),
    ],
)
def test_transport_errors_are_sanitized(error, message):
    def handler(request):
        raise error("PRIVATE_TRANSPORT_DETAIL", request=request)

    with pytest.raises(OllamaClientError, match=message) as caught:
        client_for(handler).generate("PRIVATE_PROMPT")
    assert "PRIVATE" not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("body", [b"not json", b"{", b"\xff", b"[" * 1500])
def test_malformed_json(body):
    with pytest.raises(OllamaClientError, match="malformed JSON"):
        client_for(lambda request: httpx.Response(200, content=body)).generate("test")


@pytest.mark.parametrize(
    "payload",
    [
        None, [], "text", 1, {},
        {"done": True, "done_reason": "stop"},
        {"response": "ok", "done_reason": "stop"},
        {"response": "ok", "done": False, "done_reason": "stop"},
        {"response": "ok", "done": 1, "done_reason": "stop"},
        {"response": "ok", "done": "true", "done_reason": "stop"},
        *[{"response": value, "done": True, "done_reason": "stop"} for value in [None, 1, [], {}, "", " \n", "\ud800"]],
    ],
)
def test_invalid_fields(payload):
    # ASCII escaping lets us test an invalid Unicode escape inside otherwise valid JSON.
    body = json.dumps(payload).encode("ascii")
    with pytest.raises(OllamaClientError, match="invalid response"):
        client_for(lambda request: httpx.Response(200, content=body)).generate("test")


@pytest.mark.parametrize("text", ["x" * (MAX_OUTPUT_BYTES + 1), "é" * (MAX_OUTPUT_BYTES // 2 + 1)])
def test_oversized_output(text):
    with pytest.raises(OllamaClientError, match="output exceeds"):
        client_for(lambda request: httpx.Response(200, json={"response": text, "done": True, "done_reason": "stop"})).generate("test")


def test_output_at_limit():
    text = "x" * MAX_OUTPUT_BYTES
    assert client_for(lambda request: httpx.Response(200, json={"response": text, "done": True, "done_reason": "stop"})).generate("test") == text


def test_streaming_body_limit_without_content_length():
    chunks_read = []

    class LargeBody(httpx.SyncByteStream):
        def __iter__(self):
            for index in range(100):
                chunks_read.append(index)
                yield b"x" * 4096

    with pytest.raises(OllamaClientError, match="response exceeds"):
        client_for(lambda request: httpx.Response(200, stream=LargeBody())).generate("test")
    assert len(chunks_read) == MAX_BODY_BYTES // 4096 + 1


def test_compressed_response_is_rejected():
    with pytest.raises(OllamaClientError, match="invalid response"):
        client_for(lambda request: httpx.Response(200, headers={"content-encoding": "gzip"})).generate("test")
