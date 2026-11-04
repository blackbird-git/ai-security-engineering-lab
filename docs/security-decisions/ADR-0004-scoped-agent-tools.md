# ADR-0004: Scoped agent tools and fixture service identities

- Status: Accepted
- Date: 2026-11-04
- Scope: Internal, single-step synthetic read tools; no public agent endpoints

## Decision and request boundary

Accepted for the implemented fixture-based internal authorization framework and tested read-only tools only. This does not authorize public agent endpoints, real service authentication, real secrets, or production deployment.

Use `app.agent_tools.execute_tool(service, model_request)` as the only tool dispatcher. Trusted harness code supplies a frozen `ServiceIdentity` with a subject only; permissions and customer scopes come from an immutable application policy, never the model. This is fixture context, not real service authentication or an unforgeable Python capability.

The explicit allowlist is `get_customer_account` and `get_customer_transactions`. There is no dynamic import, function-name evaluation, shell, Python interpreter, file reader, credential accessor, or network tool. Each call validates the service, parses strict JSON, validates the tool/arguments, checks service permission and customer scope, then uses a trusted customer-to-caller mapping to invoke the existing `read_customer` boundary. That reader independently verifies its caller/customer relationship. Model content cannot select the mapped caller, modify policy, or elevate permissions.

| Service fixture | Allowed tools | Customer scope |
| --- | --- | --- |
| `svc-amber-account` | `get_customer_account` | `SYN-C001` |
| `svc-basil-transactions` | `get_customer_transactions` | `SYN-C002` |
| `svc-amber-reader` | Both allowlisted tools | `SYN-C001` |
| `svc-no-access` | None | None |
| Unknown subject | None | None |

Requests must be UTF-8 strings of at most 2,048 bytes and exactly `{"tool": ..., "arguments": ...}`. Duplicate keys, nonstandard JSON constants, extra fields, lists/chains, unknown tools, identity/permission overrides, and invalid argument types fail closed. Account arguments contain only a known authorized `customer_id`. Transaction arguments require exactly `customer_id` and integer `limit` in 1..5; booleans and floats are rejected. A fixed finite policy bounds customer identifiers and tool names without accepting arbitrary paths or URLs.

Account results contain only the synthetic label, customer ID, and balance in integer cents. Transaction results contain the label, customer ID, and at most five transaction projections. Results are detached from immutable fixtures and bounded to 4,096 UTF-8 JSON bytes before return. Read failures, export violations, and denials use the same fixed `ToolDenied` message, with no request data or secret details. Tool results remain untrusted data, never authority or executable instructions.

## Single-step orchestration and demonstrations

`app.scoped_agent.run_agent` sends a fixed task/tool-schema prompt to one trusted generation callable, accepts one proposal, and dispatches once. No autonomous tool chain, retry, result feedback, or second model call exists. The default CLI uses mocked proposals with a fixed `svc-amber-account` context and checks allowed access plus cross-customer, unknown-tool, privilege-escalation, and service-permission denials. Status output contains no financial payloads, prompts, or model text.

An optional `--run-live` CLI branch uses the unchanged local `OllamaClient` and its fixed `qwen3:4b-instruct` model. It generates once and subjects the result to the same dispatcher. It is disabled by default. After implementation, the owner verified one authorized read executed, with the result withheld from output and model; see the validation record. Live attack scenarios remain unverified. No external network operation or package installation is needed or performed. The opt-in branch uses loopback only; it does not grant the model network access. Denial is an experimental outcome, not a CLI execution failure; generation failure returns exit 1.

## Dummy secrets boundary

`app/secrets_boundary.py` holds a clearly dummy-only sentinel independently of synthetic financial fixtures. No credential files or environment secrets are loaded. The model-facing prompt is fixed and contains no secret; tool output is an allowlisted projection, with no secret retrieval operation. An exact sentinel export check rejects contaminated prompts, proposals, and outputs. Exceptions and CLI output omit raw values. This is an educational separation/export guard, not a general secret scanner: encoded/unknown secrets are not detected, and arbitrary local Python code can import the dummy value. Real secrets remain prohibited.

## Security consequences and limitations

Service action permission and customer permission must both pass on every execution; model compliance is unnecessary for authorization. Unknown/malformed requests are denied before data access. No FastAPI routes, existing model configuration, Wazuh settings, or previous lab behavior are changed. Run FastAPI on `127.0.0.1` using the established command.

This relies on trusted host code and correct policy configuration. There is no real authentication, process isolation, service credential lifecycle, policy administration, audit backend, rate limiting, or total inference deadline. The fixed customer-to-caller translation is a trusted deputy and must not become user-controlled. Extending either allowlist or policy requires review and negative tests. The live model may emit invalid JSON or a rejected length-limited response; the single authorized live result does not establish live attack resistance. Ollama does not authenticate local clients in this lab configuration. No production-ready service identity or secrets-management integration exists. Existing Starlette/HTTPX warning, unauthenticated loopback inference, and deadline limitations remain. Any public/authenticated service integration requires separate review.

See the [Milestone 5 validation record](../validation/milestone-05-scoped-agent-tools.md) for executed checks and observations.
