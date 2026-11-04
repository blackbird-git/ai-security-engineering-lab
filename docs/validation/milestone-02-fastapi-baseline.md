# Milestone 2: Minimal FastAPI baseline validation

- Validation date: November 4, 2026
- Status: Complete for the owner-approved minimal FastAPI baseline; code review passed
- Repository: `.`
- Python: 3.14.4, using the repository's existing `.venv`

## Scope and evidence provenance

This record covers the static health endpoint, disabled API documentation routes, dependency consistency, and the live IPv4 loopback listener. The owner confirmed code review and live validation results. Automated results were recorded during implementation; manual live results below are owner-reported observations. These checks were not rerun when preparing this record, apart from the requested documentation whitespace check.

Commands below show how to reproduce the checks from the repository root; original live command transcripts and process identifiers are not stored in the repository. Observed results summarize the verified outcomes rather than reconstructing raw output.

## Automated tests and command checks

| Command | Expected result | Observed result |
| --- | --- | --- |
| `.venv/bin/python -m pytest -q` | All 12 tests pass. | 12 passed outside the Codex sandbox; implementation run reported 0.20s and one deprecation warning. |
| `.venv/bin/python -m pip check` | Exit successfully with no broken dependencies. | No broken requirements found. |
| `git diff --check` | Exit successfully with no whitespace errors. | Passed. |

The automated tests use an in-process TestClient. They verify HTTP 200 and the exact JSON object `{"status": "ok"}` for `/healthz`, HTTP 404 for undefined routes, HTTP 404 for `/docs`, `/docs/oauth2-redirect`, `/redoc`, and `/openapi.json`, and HTTP 405 for POST, PUT, PATCH, and DELETE at `/healthz`. They do not open or verify a live TCP listener.

## Manually observed live HTTP and listener checks

Start the service in one terminal from the repository root:

```bash
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Run the following checks in another terminal on the same host while Uvicorn is running:

| Reproduction command | Expected result | Observed result reported by owner |
| --- | --- | --- |
| `curl -sS -i --max-time 5 http://127.0.0.1:8000/healthz` | HTTP 200 and JSON `{"status": "ok"}`. | HTTP 200 and `{"status":"ok"}`. |
| `curl -sS -i --max-time 5 http://127.0.0.1:8000/docs` | HTTP 404. | HTTP 404. |
| `curl -sS -i --max-time 5 http://127.0.0.1:8000/openapi.json` | HTTP 404. | HTTP 404. |
| `ss -ltnp '( sport = :8000 )'` | Uvicorn listening on `127.0.0.1:8000`. | `ss -ltnp` confirmed Uvicorn listening on `127.0.0.1:8000`. |

Stop Uvicorn with Ctrl+C after validation. The automated tests cover ReDoc and the Swagger redirect route; separate manual live observations for those routes are not recorded here.

## Unresolved observations

1. TestClient hung within the Codex sandbox, while all tests passed outside it. The hung sandbox run was stopped. The root cause is not established; passing outside the sandbox does not prove that a particular sandbox restriction caused the hang.
2. A Starlette/HTTPX deprecation warning was reported. Its exact cause and remediation remain unverified. No dependency change or additional package installation was made to address it.

## Limitations and follow-up scope

- Milestone 2 completion applies to the minimal FastAPI baseline. Ollama integration, including the earlier FastAPI-to-Ollama smoke-check objective, is planned for Milestone 3; no Ollama connectivity is demonstrated here.
- `/healthz` reports static application liveness only. It does not verify model availability, data access, telemetry, or downstream service health.
- Authentication, authorization, financial records, agent tools, and Wazuh integration are not implemented. Sensitive capabilities must remain unavailable until appropriate controls are implemented and tested.
- Loopback binding was observed for the validated run. It does not enforce future launch settings or establish isolation against local processes, forwarding, proxies, or container configuration.
- Disabled documentation endpoints reduce the route surface but do not supply authentication or authorization.
- `pip check` verifies installed dependency consistency; it is not a vulnerability assessment. Pinned versions do not constitute a package hash lock.
- These results do not establish production readiness, performance, or comprehensive security assurance. Resolve the two observations in separately scoped follow-up work.
