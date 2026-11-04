# AI Security Engineering Lab

A hands-on training and portfolio project for LLM and agent security, application authorization, security telemetry, and detection engineering. Work uses local inference and synthetic financial data. It does not represent a production financial service or a claim of production AI security or SOC experience.

## Current status

Milestone 2's minimal FastAPI baseline passed code review and automated and live validation on November 4, 2026. It implements only `GET /healthz`, returning `{"status": "ok"}`, with Uvicorn verified listening on `127.0.0.1:8000`. Swagger, ReDoc, and OpenAPI endpoints are disabled. Milestone 3 is complete for the internal local Ollama client; FastAPI-to-Ollama integration, authentication, financial data, agent tools, and Wazuh integration are not implemented. See the [validation record](docs/validation/milestone-02-fastapi-baseline.md) for baseline evidence and limitations.

The normal inference model is `qwen3:4b-instruct`; `qwen3:4b` is retained as an experimental thinking model and is not selectable through the fixed-model client. The owner verified a direct Ollama API result of `LAB_READY` with `done: true` and `done_reason: "stop"` for the instruct variant. The owner also verified that the updated Python client returned `LAB_READY`; see the [Milestone 3 validation record](docs/validation/milestone-03-ollama-integration.md). Instruction-following does not establish model trustworthiness. See [ADR-0002 (Accepted)](docs/security-decisions/ADR-0002-local-ollama-client.md) and [Investigation 001](docs/investigations/001-ollama-generation-truncation.md).

Owner-verified environment: Ubuntu 26.04 LTS, Python 3.14.4, Docker 29.8.2, Ollama 0.40.13, and Qwen3 4B. Wazuh 4.14.9 is the intended telemetry destination. Compatibility and integration remain to be tested.

## Planned architecture

```text
Lab client
    |
    v
Python FastAPI (trusted identity, validation, authorization)
    |
    v
Local Ollama / qwen3:4b-instruct (untrusted proposals)
    |
    v
Application tool dispatcher (authorization on each action/resource)
    |
    v
Controlled agent tools -> synthetic financial data

FastAPI + dispatcher + tools
    -> redacted structured security telemetry
    -> approved collection path -> Wazuh 4.14.9
```

The diagram shows logical flow, not direct model access to tools. Application code mediates model requests and tool results. Prompts cannot grant permissions. Services default to loopback or an isolated lab network; the model has no direct filesystem, shell, internet, or Wazuh administration access.

## Objectives

- Build and test application-enforced authorization for a tool-using local model.
- Explore prompt injection, untrusted retrieval, and attempted tool misuse in isolated scenarios.
- Demonstrate least privilege and synthetic data isolation with both permitted and denied cases.
- Produce redacted security events and evaluate useful Wazuh detections with reproducible evidence.
- Document limitations and findings accurately enough for portfolio review.

## Eight development milestones

Milestone 1's scope and trust-boundary principles are accepted in ADR-0001. Milestone 2 is complete for the owner-approved minimal FastAPI baseline. Milestone 3 is complete for the owner-approved internal Ollama client only; synthetic data and later work remain planned. Each requires evidence before it is marked complete.

| # | Milestone | Completion evidence |
| --- | --- | --- |
| 1 | Scope, trust boundaries, and standards | Reviewed README, agent instructions, ignore rules, and ADR-0001; unresolved decisions recorded. |
| 2 | Minimal FastAPI baseline — complete | Code review passed; 12 tests passed; dependency and whitespace checks passed; live health/docs checks and loopback binding verified. See the [validation record](docs/validation/milestone-02-fastapi-baseline.md). Internal Ollama integration is covered by Milestone 3. |
| 3 | Internal local Ollama client — complete | ADR-0002 accepted for internal inference only; 85 tests passed, dependency and whitespace checks passed, incomplete generation rejected, and direct API and Python-client `LAB_READY` results owner-verified. See the [validation record](docs/validation/milestone-03-ollama-integration.md). Synthetic financial data remains future work. |
| 4 | Application identity and authorization | Explicit role/action/resource policy with positive and negative tests, including cross-user access attempts. |
| 5 | Controlled agent tools | Narrow tool contracts, per-invocation authorization, validated arguments/results, execution limits, and denied misuse tests. |
| 6 | Isolated adversarial exercises | Reproducible prompt-injection and tool-abuse cases with bounded targets, expected outcomes, and regression tests. |
| 7 | Security telemetry and Wazuh | Reviewed event schema and redaction tests; separately approved Wazuh integration with verified event delivery and detection results. |
| 8 | Evidence and portfolio review | Reproducible walkthrough, sanitized test/detection evidence, documented limitations, and accurate statements of demonstrated skills. |

## Working standards

See [AGENTS.md](AGENTS.md) for coding-agent requirements and [ADR-0001](docs/security-decisions/ADR-0001-scope-and-trust-boundaries.md) for the accepted scope and trust-boundary principles and pending implementation decisions. Use small changes with security-focused tests. Keep secrets and sensitive local artifacts out of Git; ignore patterns are only a supporting safeguard and do not sanitize tracked files.

GitHub pushes, external operations, and Wazuh modifications require explicit approval. The minimal health application and its PyPI dependencies were previously authorized; new work requires authorization for its scope. No commit or push is currently authorized.

## Run the minimal application

Run from this repository using its existing Python 3.14.4 virtual environment. Following approval for dependency downloads, install the exact resolved application and test dependencies:

```bash
.venv/bin/python -m pip install --index-url https://pypi.org/simple -r requirements.txt
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The explicit host binds the server to IPv4 loopback. Do not change it to `0.0.0.0` or expose it through a proxy or container port mapping. From the same host, `GET http://127.0.0.1:8000/healthz` returns HTTP 200 with `{"status": "ok"}`. Stop the server with Ctrl+C. The endpoint reports application liveness only; it does not check Ollama or any other dependency.

Until appropriate authentication and authorization controls are implemented, only static diagnostics may be exposed. Disabling API documentation reduces the exposed route surface; it does not provide authentication or authorization.

## Python concepts in this increment

- `app/__init__.py` identifies `app` as a Python package. `app/main.py` is a module within that package.
- `from fastapi import FastAPI` imports the framework's application class. `app = FastAPI(...)` creates an instance that holds route registrations and handles requests. Setting `docs_url`, `redoc_url`, and `openapi_url` to `None` disables their HTTP endpoints.
- `@app.get("/healthz")` is a route decorator: it registers the function below it to handle HTTP GET requests at that path.
- `def healthz() -> dict[str, str]:` defines the endpoint function. The return annotation describes a dictionary with string keys and values; the function returns a static Python dictionary, which FastAPI serializes to JSON.
- In Uvicorn's `app.main:app`, `app.main` names the module and the final `app` names its FastAPI instance. Uvicorn provides the HTTP server; its command-line host setting controls the network binding.

## Validation

Run from the repository root:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
git diff --check
git status --short
```

Tests use an in-process HTTP client and check the exact health response, undefined routes, disabled documentation endpoints, and rejected write methods. `requirements.txt` pins the resolved direct and transitive application/test dependency versions; it is not a package hash lock or a vulnerability assessment.

The [November 4, 2026 validation record](docs/validation/milestone-02-fastapi-baseline.md) separates automated evidence from manually observed live HTTP and listener checks. All 12 baseline tests passed, dependencies were consistent, and live checks verified the health endpoint, disabled documentation routes, and loopback binding. The sandbox TestClient hang and Starlette/HTTPX deprecation warning remain unresolved observations; their causes and remediation are unverified. The subsequent direct Ollama API and Python-client results are documented separately in the [Milestone 3 validation record](docs/validation/milestone-03-ollama-integration.md). They do not authorize public inference, sensitive data access, or tools.
