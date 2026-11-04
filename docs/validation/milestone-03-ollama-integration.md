# Milestone 3: Internal local Ollama integration validation

- Validation date: November 4, 2026
- Status: Complete for the internal local Ollama client only
- Decision: [ADR-0002](../security-decisions/ADR-0002-local-ollama-client.md), Accepted
- Investigation: [001: Ollama generation truncation](../investigations/001-ollama-generation-truncation.md)
- Repository: `.`

## Scope and evidence provenance

The owner verified the automated and manually observed live results below. Automated tests exercise mocked HTTPX transports and the existing health endpoint; they do not contact live Ollama. Live results came from separate manual integration checks reported by the owner. No tests, live requests, or package operations were rerun for this documentation task; only the requested Git checks were run.

This milestone covers the internal Python client only. It does not authorize public inference endpoints, sensitive data access, or tools. FastAPI still exposes only the static health diagnostic. Synthetic financial data remains future work.

## Automated tests and command checks

Run from the repository root:

| Command | Expected result | Owner-verified observed result |
| --- | --- | --- |
| `.venv/bin/python -m pytest -q` | All tests pass without live inference requests. | 85 passed: 73 client tests and 12 health tests. |
| `.venv/bin/python -m pip check` | No broken installed dependency requirements. | No broken requirements found. |
| `git diff --check` | No whitespace errors. | Passed. |

The latest recorded implementation run passed in 0.31 seconds outside the sandbox, with one existing Starlette/HTTPX deprecation warning. Tests cover fixed request parameters, input validation, body/output limits, completion validation, malformed responses, and sanitized HTTP/transport/timeout failures. They are distinct from the manual live observations below.

## Manually observed live integration results

| Manual check | Expected behavior | Owner-verified observed result |
| --- | --- | --- |
| Original `qwen3:4b` generation | Suitable completed text for the initial normal-operation workflow. | `done=true`, `done_reason=length`, and incomplete reasoning-like text (587 characters). The original client incorrectly accepted it. |
| Corrected client with incomplete generation | Reject non-stop completion without exposing content or metadata. | Rejected with `Ollama returned an invalid completion.` |
| Direct Ollama API test using `qwen3:4b-instruct` | Stop completion with the requested readiness response. | `done=true`, `done_reason=stop`, response `'LAB_READY'`. |
| Updated Python `OllamaClient` using `qwen3:4b-instruct` | Return the readiness text after client validation. | Returned `'LAB_READY'`. |

These rows summarize supplied live results. Exact original prompts, full commands, and raw transcripts are not reproduced here; no new live checks were performed. The direct API result and Python-client return are separate observations. The Python-client observation establishes this narrow successful integration, not reliability across arbitrary prompts or verification of every server option.

## Validated client design and trust boundary

| Control | Implemented requirement |
| --- | --- |
| Destination and model | Fixed `http://127.0.0.1:11434/api/generate` and `qwen3:4b-instruct`; no caller-supplied URL or model. `qwen3:4b` remains an experimental thinking model outside this client. |
| Request parameters | `stream=false`, `think=false`, `options.num_predict=128`. |
| Input | Nonempty string after whitespace checking, at most 2,000 Python characters, UTF-8 encodable; accepted text is preserved. |
| Network behavior | `trust_env=False`, redirects disabled; connect/read/write/pool timeouts of 3/60/5/3 seconds respectively. |
| Response envelope | HTTP 200; identity encoding; at most 65,536 body bytes, read in 4,096-byte chunks; UTF-8 JSON object. |
| Completion | `done` must be exactly `true` and `done_reason` exactly `"stop"`; missing, invalid, or other reasons fail. |
| Output | Nonempty UTF-8 encodable response string, at most 8,192 UTF-8 bytes. |
| Error handling | Fixed sanitized errors for malformed responses, incomplete completion, HTTP errors, connection failures, timeouts, and size violations; no raw prompts, model text, or response metadata in errors. No client logging of raw content. |

Model output remains untrusted text. Instruction-following, valid JSON, and a stop completion do not establish truth, semantic completeness, safety, or authorization. Output must never grant permissions, trigger tools, or become executable instructions.

## Remaining limitations

- Local HTTP inference is not authenticated. Loopback addressing does not prove that the intended Ollama process is listening or protect against malicious local processes.
- Timeouts apply to individual network operations; there is no absolute request deadline. A slow trickle may extend total duration.
- No retries, concurrency controls, cancellation controls, or server-side compute quotas are implemented. The 128-token setting is a server request, not an independently enforced compute limit, and may still produce rejected length-limited output.
- The cause of the thinking model's reasoning-like output and its handling of `think=false` remain unverified. The model comparison is not a controlled benchmark.
- The narrow `LAB_READY` checks do not establish broad model reliability, latency guarantees, or production readiness.
- The TestClient sandbox hang has no established root cause. The Starlette/HTTPX warning's exact cause and remediation remain unverified.
- Authentication/authorization for application inference, public inference routes, sensitive data, financial fixtures, tools, and Wazuh integration remain outside this accepted decision and completed milestone.
