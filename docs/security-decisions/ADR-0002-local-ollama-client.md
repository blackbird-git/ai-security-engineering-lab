# ADR-0002: Internal local Ollama client

- Status: Accepted
- Date: 2026-11-04
- Scope: Milestone 3's first internal inference client; no public API integration

## Context and decision

The owner approved this decision for the internal local Ollama client only. Acceptance does not authorize public inference endpoints, sensitive data access, or tools. Those capabilities require separately reviewed designs, appropriate authentication and authorization, and explicit authorization for implementation.

Use the existing HTTPX dependency for a synchronous `OllamaClient.generate(prompt)` method. Its destination is fixed to `http://127.0.0.1:11434/api/generate` and its model to `qwen3:4b-instruct`. Callers cannot supply a URL, model, headers, or generation options. A transport may be injected by trusted test code for HTTPX MockTransport; it is not an application input or an isolation mechanism against malicious Python code.

Select the instruct variant for the initial normal-operation workflow. The retained experimental thinking model, `qwen3:4b`, produced incomplete reasoning-like text and a length-limited completion in the observed test, making it unsuitable for that initial workflow under the tested configuration. The owner subsequently verified a successful direct Ollama API test with `qwen3:4b-instruct`: `done: true`, `done_reason: "stop"`, and response `LAB_READY`. This narrow result supports selecting the instruct variant; it does not establish reliability across prompts or prove why the thinking variant behaved that way. Instruction-following does not establish model trustworthiness, and all existing validation and trust boundaries remain necessary.

Send `stream: false`, `think: false`, and `options.num_predict: 128`. Prompts must be nonempty strings after whitespace checking, at most 2,000 Python characters, and UTF-8 encodable. Preserve accepted prompt text rather than silently trimming it. The client never logs prompts or model responses.

Use explicit timeouts: connection 3 seconds, read 60 seconds, write 5 seconds, and pool 3 seconds. Disable environment-derived configuration with `trust_env=False` and redirects with `follow_redirects=False` so proxy settings and HTTP redirects cannot select a different destination.

Accept only HTTP 200. Bound the response body to 65,536 bytes while reading in 4,096-byte chunks, without relying on Content-Length. Request identity encoding and reject compressed responses to avoid decompression expansion. Decode UTF-8 JSON and require an object with `done` exactly `true`, `done_reason` exactly `"stop"`, and a nonempty string `response`. Missing, invalid, or non-stop completion reasons fail with a fixed `OllamaClientError` that includes no model text or response metadata. Bound generated text to 8,192 UTF-8 bytes. Other metadata is ignored; only the validated text is returned. These conservative byte limits bound parsing and output separately from the model's requested token limit.

Connection failures, timeouts, other HTTPX request errors, unsuccessful HTTP statuses, invalid bodies, and excessive sizes produce fixed `OllamaClientError` messages. Invalid prompts produce fixed `ValueError` messages. Do not include server error bodies, prompts, model text, or underlying exception details in reported errors; suppress chained transport/parse exceptions in normal tracebacks.

## Trust boundary

Loopback inference is a separate, untrusted service. A valid JSON response is not evidence of truth, authorization, or safety. Returned text must remain untrusted data: never execute it, interpret it as application policy, or let it grant tool privileges. This module has no tools, financial records, authentication, or FastAPI endpoints and does not change `/healthz`.

Local HTTP does not authenticate the listening process. Trusting the host and the intended Ollama listener remains an assumption. The fixed destination and disabled redirects restrict this client's request destination; they do not sandbox Ollama or enforce its own network behavior.

## Validation and limitations

Tests inject HTTPX MockTransport and perform no real network requests. They cover request destination/options/timeouts, disabled environment configuration and redirects, prompt validation, valid output, HTTP/connection/timeout failures, malformed JSON, invalid fields, and bounded body/output handling. Run `.venv/bin/python -m pytest -q`, `.venv/bin/python -m pip check`, and `git diff --check`; record observed results separately from this design.

Observed on November 4, 2026: all 56 client tests passed inside the sandbox; the full suite passed all 68 tests in 0.30 seconds outside the sandbox due to the previously observed health TestClient hang. One existing Starlette/HTTPX deprecation warning remained. `pip check` found no broken requirements and `git diff --check` passed. No dependencies were changed, and no live Ollama request was made.

Subsequent owner-reported live testing exposed a limitation: `qwen3:4b` returned `done: true` with `done_reason: "length"` and 587 characters of incomplete reasoning-like text. The original client incorrectly accepted it. See [Investigation 001](../investigations/001-ollama-generation-truncation.md) for the observation, correction, and model comparison. This establishes that `done` alone is insufficient; it does not establish why reasoning-like text appeared or whether the model honored `think: false`. The completion-validation fix initially left the model unchanged; the current selection changes only the fixed model to `qwen3:4b-instruct`, retaining `num_predict: 128`. A stop completion is a protocol check, not proof of a complete, correct, or safe answer.

After the completion-validation correction, all 85 tests passed (73 client tests plus 12 health tests); `pip check` and `git diff --check` passed. The existing Starlette/HTTPX warning remained. This validation used mocks and did not contact live Ollama; ADR status was Proposed at that stage.

After selecting `qwen3:4b-instruct`, the full mock-based suite again passed all 85 tests in 0.31 seconds outside the sandbox. The request test verifies the new fixed model and unchanged generation parameters; all negative tests remain intact. `pip check` found no broken requirements and `git diff --check` passed. The existing Starlette/HTTPX warning remained. No packages were installed and no live requests were made during this update.

No package download or live Ollama request is authorized for this model-selection change. The owner subsequently verified that the updated Python client returned `LAB_READY`; see the [Milestone 3 validation record](../validation/milestone-03-ollama-integration.md). These narrow direct API and Python-client results do not verify general support for all requested options, reliability across prompts, or real latency. Read timeouts apply per read rather than as a total request deadline; a slow trickle can extend total duration. There are no retries, concurrency limits, cancellation controls, or server-side compute quotas. `num_predict` is a request to the server, not an independently enforced compute limit. Callers must not supply secrets, and future telemetry must avoid raw content. Review these limits and service authentication before integrating inference into application flows.
