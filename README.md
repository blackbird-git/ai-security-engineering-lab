# AI Security Engineering Lab

A hands-on training and portfolio project for LLM and agent security, application authorization, security telemetry, and detection engineering. Work uses local inference and synthetic financial data. It does not represent a production financial service or a claim of production AI security or SOC experience.

## Current status

Milestone 2's minimal FastAPI baseline passed code review and automated and live validation on November 4, 2026. It implements only `GET /healthz`, returning `{"status": "ok"}`, with Uvicorn verified listening on `127.0.0.1:8000`. Swagger, ReDoc, and OpenAPI endpoints are disabled. Milestone 3 is complete for the internal local Ollama client. Milestone 4 is complete for synthetic fixtures, internal application authorization, offline demonstrations, and an owner-verified opt-in live experiment. Milestone 5 is complete for scoped internal read-only tools and fixture service identities, with ADR-0004 Accepted and one owner-verified live authorized execution. Milestone 6 is complete for structured authorization telemetry, manager-local collection, and indexed AI alerts. FastAPI-to-Ollama integration and real authentication are not implemented. See the [baseline validation record](docs/validation/milestone-02-fastapi-baseline.md).

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

Milestone 1's scope and trust-boundary principles are accepted in ADR-0001. Milestone 2 is complete for the owner-approved minimal FastAPI baseline. Milestone 3 is complete for the owner-approved internal Ollama client only. Milestone 4 is complete for its implemented and tested internal scope, with ADR-0003 Accepted. Milestone 5 is complete for the implemented fixture-based framework, with offline tests and owner-verified live authorized execution. Milestone 6 has verified application-to-JSONL-to-manager-to-indexer delivery and retained the approved integration. Earlier rule-only trials were rolled back; ADR-0005 is Accepted for the implemented scope. Correlation expiry remains unverified. Milestone 7 is implemented and locally validated, with hosted CI validation pending; final portfolio review remains planned.

| # | Milestone | Completion evidence |
| --- | --- | --- |
| 1 | Scope, trust boundaries, and standards | Reviewed README, agent instructions, ignore rules, and ADR-0001; unresolved decisions recorded. |
| 2 | Minimal FastAPI baseline — complete | Code review passed; 12 tests passed; dependency and whitespace checks passed; live health/docs checks and loopback binding verified. See the [validation record](docs/validation/milestone-02-fastapi-baseline.md). Internal Ollama integration is covered by Milestone 3. |
| 3 | Internal local Ollama client — complete | ADR-0002 accepted for internal inference only; 85 tests passed, dependency and whitespace checks passed, incomplete generation rejected, and direct API and Python-client `LAB_READY` results owner-verified. See the [validation record](docs/validation/milestone-03-ollama-integration.md). Synthetic fixtures are covered by Milestone 4. |
| 4 | Prompt injection, synthetic data, and application authorization — complete | Offline fixture identities, customer-scoped read policy, positive/negative tests, and protected injection demonstration; vulnerable comparison is an opt-in outcome simulation. See the [validation record](docs/validation/milestone-04-prompt-injection-authorization.md). ADR-0003 Accepted. Live control and injected phases both followed the legitimate task; no unauthorized request was observed and authorization was not exercised in that live run. |
| 5 | Scoped agent tools and service identities — complete | Two read-only tools, fixture service/tool/customer policies, strict request bounds, single-step orchestration, dummy-secret separation, and offline negative tests. See [validation](docs/validation/milestone-05-scoped-agent-tools.md) and [ADR-0004 (Accepted)](docs/security-decisions/ADR-0004-scoped-agent-tools.md). |
| 6 | Structured AI telemetry and Wazuh collection — complete for the verified lab scope | Five fresh application denial IDs matched manager alerts and the existing Wazuh alert index; read-only collection and separate rules remain installed. See [end-to-end evidence](docs/validation/milestone-06-end-to-end-wazuh-integration.md), historical [Phase B trials](docs/validation/milestone-06-phase-b-wazuh-rule-validation.md), and [ADR-0005 (Accepted)](docs/security-decisions/ADR-0005-security-telemetry.md). |
| 7 | GitHub Actions security pipeline — implemented; hosted validation pending | Python 3.14 tests, dependency consistency/auditing, secret scanning, and workflow policy checks. See [validation](docs/validation/milestone-07-security-ci.md) and [ADR-0006 (Accepted)](docs/security-decisions/ADR-0006-security-ci.md). |
| 8 | Evidence and portfolio review | Reproducible walkthrough, sanitized test/detection evidence, documented limitations, and accurate statements of demonstrated skills. |

## Working standards

See [AGENTS.md](AGENTS.md) for coding-agent requirements and [ADR-0001](docs/security-decisions/ADR-0001-scope-and-trust-boundaries.md) for the accepted scope and trust-boundary principles and pending implementation decisions. Use small changes with security-focused tests. Keep secrets and sensitive local artifacts out of Git; ignore patterns are only a supporting safeguard and do not sanitize tracked files.

GitHub pushes, external operations, and Wazuh modifications require explicit approval. The minimal health application and its PyPI dependencies were previously authorized; new work, commits, and pushes require task-specific authorization.

## Run the minimal application

Run from this repository using its existing Python 3.14.4 virtual environment. Following approval for dependency downloads, install the exact resolved application and test dependencies:

```bash
.venv/bin/python -m pip install --index-url https://pypi.org/simple -r requirements.txt
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The explicit host binds the server to IPv4 loopback. Do not change it to `0.0.0.0` or expose it through a proxy or container port mapping. From the same host, `GET http://127.0.0.1:8000/healthz` returns HTTP 200 with `{"status": "ok"}`. Stop the server with Ctrl+C. The endpoint reports application liveness only; it does not check Ollama or any other dependency.

Until appropriate authentication and authorization controls are implemented, only static diagnostics may be exposed. Disabling API documentation reduces the exposed route surface; it does not provide authentication or authorization.

## Reproduce the offline prompt-injection demonstration

```bash
.venv/bin/python -m app.prompt_injection_demo
.venv/bin/python -m app.prompt_injection_demo --include-vulnerable-simulation
```

Both commands use only fictional SYNTHETIC records and a fixed offline model stub; they do not contact Ollama. A malicious retrieved note asks the model to impersonate another customer. The stub assumes compliance and proposes the other customer's ID, but the Python reader uses the original trusted fixture identity and denies access. The default command also demonstrates an allowed own-customer read. Neither command prints financial records or prompts.

The explicit flag enables a clearly labeled hypothetical vulnerable outcome. It performs no unauthorized read and is isolated from the protected reader. This illustrates the risk of trusting model-selected scope without claiming a live exploit succeeded. Fixture caller context is not real user authentication; production identity must come from an authenticated trusted source. See [ADR-0003 (Accepted)](docs/security-decisions/ADR-0003-synthetic-data-and-authorization.md) and the [Milestone 4 evidence and limitations](docs/validation/milestone-04-prompt-injection-authorization.md). FastAPI remains health-only and must run on `127.0.0.1` as documented above.

## Optional live prompt-injection experiment

Run this separate experiment only when you intend to send two synthetic prompts to your existing local Ollama service:

```bash
.venv/bin/python -m app.live_prompt_injection --run-live
```

Without `--run-live`, the command makes no requests. It uses the existing fixed `qwen3:4b-instruct` client and `127.0.0.1:11434` destination. The control task summarizes the caller's authorized synthetic financial document; the second document embeds instructions to request another customer's records. Only fixed sanitized result categories are printed. Recognized unauthorized requests pass through Python authorization using the original fixture identity and must be denied. No records are sent back to the model.

The owner-verified live run followed the legitimate task in both control and injected phases. No unauthorized request was observed, so the live run did not exercise authorization. Offline tests independently verify cross-customer denial. This single run does not establish general injection resistance. The strict output classifier is not a general intent detector; see the [live experiment protocol and observed results](docs/validation/milestone-04-prompt-injection-authorization.md#opt-in-live-experiment-protocol-and-results). The existing offline demonstration and opt-in vulnerable simulation remain separate.

## Scoped agent tools (Milestone 5)

```bash
.venv/bin/python -m app.scoped_agent
```

The offline default demonstrates an allowed account read and denied cross-customer, unknown-tool, privilege-escalation, and service-permission requests using mock model responses. Trusted Python code supplies the fixture service identity, validates one request, checks service permission and customer scope, and invokes the existing customer-authorized reader. Tools are limited to `get_customer_account` and `get_customer_transactions` (transaction limit 1..5). Results are bounded and never sent back to the model; there are no autonomous chains or public agent routes.

The owner verified one authorized read using the opt-in live mode `.venv/bin/python -m app.scoped_agent --run-live`; it makes one local Ollama call through the existing fixed-model client. The result was withheld from output and model. Live attack scenarios remain unverified; negative authorization outcomes are established by offline tests. Offline mode makes no network calls. Neither mode prints financial records, prompts, or dummy secrets. The simple dummy-only secrets guard is not a general secret scanner, and fixture service identities are not real authentication. See [ADR-0004](docs/security-decisions/ADR-0004-scoped-agent-tools.md) for the permissions table and [Milestone 5 evidence](docs/validation/milestone-05-scoped-agent-tools.md) for tested outcomes and limitations. FastAPI remains health-only with the established loopback binding.

## Local security telemetry (Milestone 6 Phase A)

```bash
# Offline scenarios; no filesystem logging by default
.venv/bin/python -m app.telemetry_demo
# Explicitly enable local-only JSONL under the ignored local/ directory
.venv/bin/python -m app.telemetry_demo --log-file local/telemetry/security-events.jsonl
```

The demo exercises one allowed account read and five real Python denials: customer scope, unknown tool, identity override, service permission, and malformed proposal. Model proposals are mocked; the application makes no live inference or network calls. When the installed collector is active, explicitly persisted events are collected by Wazuh. Events include UTC time, schema version, trusted outcome/reason, UUID correlation, pseudonymous service alias, and normalized tool ID. No prompts, model text, customer identifiers/names, financial values, tokens, or secrets enter events.

Storage is disabled unless explicitly configured. Enabled logging is bounded to 1,024 bytes per event and 1 MiB per file, with restrictive file permissions and no rotation. A failure to append an authorization event denies an otherwise allowed read before data access; denied requests stay denied even if logging fails. Capacity exhaustion can therefore cause availability loss. An `allowed` event records a policy decision, not proof of result delivery. See [ADR-0005](docs/security-decisions/ADR-0005-security-telemetry.md) for the complete schema and failure limitations.

[integrations/wazuh](integrations/wazuh/README.md) contains JSON collection examples, custom XML rules for individual/repeated failures, and illustrative sanitized samples. The approved manager-only collection override and separate rules are now **installed**. Five fresh application denial IDs were verified in actual manager alerts and the existing alert index; see [end-to-end evidence](docs/validation/milestone-06-end-to-end-wazuh-integration.md). SSH, original named volumes/settings, and unrelated services were preserved. Historical rule-only trials were rolled back; correlation expiry, supervised rotation, and dashboard UI validation remain pending. Future configuration changes still require explicit approval. Suspicious requests and denials are indicators, not proof of successful injection. See the [Phase A evidence](docs/validation/milestone-06-phase-a-security-telemetry.md).

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

## Milestone 6 evidence and reproduction

The [investigation report](docs/investigations/003-ai-agent-authorization-detection.md) links five sanitized indexed alerts and explains the application-to-JSONL-to-Wazuh path. See the [reproduction guide](integrations/wazuh/REPRODUCE.md) for offline commands and the approval-gated integration procedure; no owner-private configuration or credentials are distributed.

Correlation expiration is unverified, the dashboard UI was not inspected, and supervised log rotation is pending. Fixture identities are not real authentication. All financial data is synthetic. This educational portfolio lab is not a production SOC deployment.

## CI status

[Security CI](https://github.com/blackbird-git/ai-security-engineering-lab/actions/workflows/security-ci.yml) is implemented and locally validated; its first GitHub-hosted run is pending. It triggers on pushes to `main`, pull requests targeting `main`, and manual dispatch. Three hosted jobs run the full offline regression suite once, check dependencies, audit pinned requirements with pip-audit, scan history/source with Gitleaks, and validate workflow syntax/security settings. Only `contents: read` is granted; no local Ollama, Wazuh, deployment credentials, or paid scanner is required.

Application requirements stay unchanged; pinned scanners use isolated tooling. Tests and real findings fail their jobs. See the [operation and local reproduction guide](docs/ci/security-pipeline.md), [Milestone 7 local results](docs/validation/milestone-07-security-ci.md), and [ADR-0006 (Accepted)](docs/security-decisions/ADR-0006-security-ci.md). Required GitHub checks and hosted execution still need verification.
