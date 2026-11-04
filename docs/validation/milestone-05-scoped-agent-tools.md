# Milestone 5: Scoped agent tool validation

- Date: November 4, 2026
- Status: Complete for the implemented fixture-based framework
- Scope: Internal read-only synthetic tools and fixture service authorization
- Decision: [ADR-0004](../security-decisions/ADR-0004-scoped-agent-tools.md), Accepted

## Architecture and threat model

An untrusted model proposes a JSON tool name and arguments. Trusted Python code selects the service identity independently and applies a fixed service/tool/customer policy before any data access. Authorized requests then pass through the existing customer-level reader. Results are projected, bounded, and never fed back into the model. Attackers may propose arbitrary tools, customers, identity/permission overrides, chains, malformed JSON, or oversized content; none can grant privileges.

All financial records are fictional SYNTHETIC fixtures. The dummy secret sentinel is separated from tool data; no real secret storage or export is involved. The demonstration is not authentication, a Python sandbox, or proof of production readiness.

## Reproduction

```bash
.venv/bin/python -m app.scoped_agent
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
git diff --check
git status --short
```

The default CLI is offline, uses mocked model proposals, and must return exit 0 for the following outcomes:

| Case | Expected | Observed |
| --- | --- | --- |
| Authorized account read for `svc-amber-account` / `SYN-C001` | Allowed | Allowed. |
| Cross-customer account request for `SYN-C002` | Denied | Denied. |
| Unknown `shell` tool | Denied | Denied. |
| Model-supplied administrator identity and permissions | Denied | Denied. |
| Transaction request by account-only service | Denied | Denied. |

Executed offline CLI output:

```text
OFFLINE_SYNTHETIC: mock proposals; no live model or financial output.
authorized: allowed
cross_customer: denied
unknown_tool: denied
privilege_escalation: denied
service_permission: denied
```

These are real Python authorization outcomes over synthetic fixtures with mocked model proposals, not evidence of live model behavior or a successful prompt-injection exploit. No denied request executed a tool. The CLI withheld financial results and printed no prompts or dummy secrets.

## Automated security evidence

Tests cover service action/customer scope combinations, unknown/malformed identities, schema/type checks, duplicate keys, nonstandard JSON constants, missing/extra arguments, tool-name abuse, identity/permission spoofing at both request levels, transaction limits, data-layer denial, bounded/secret-tainted outputs, result isolation, single-step generation, chain rejection, sanitized errors, dummy-secret export guards, offline/live-mode test doubles, and unchanged health-only routes. New tests block socket connections; existing Ollama tests use mocks.

During initial implementation on November 4, 2026: all 97 new tool/agent tests passed inside the sandbox. The complete suite passed all 264 tests in 0.38 seconds outside the sandbox because of the previously observed health TestClient hang. One existing Starlette/HTTPX deprecation warning remained. `pip check` found no broken requirements and reported its disabled-cache permissions warning. `git diff --check` passed. No dependencies changed and no live inference ran during that implementation phase. The offline CLI shown above was executed successfully with exit 0.

## Owner-verified live authorized-tool execution

```bash
.venv/bin/python -m app.scoped_agent --run-live
```

This opt-in command makes one request using the existing fixed localhost Ollama client and `qwen3:4b-instruct`. The trusted service is fixed to `svc-amber-account`; it cannot be selected through model text or CLI arguments. The model only proposes an account request; the same Python policy authorizes execution. No tool output is returned to the model or printed. The owner executed this command and verified the following exact output (one line):

```text
LIVE_LOCAL_SYNTHETIC: one authorized read executed; result withheld from output and model.
```

This demonstrates one live Ollama proposal accepted by the Python authorization framework and one authorized read, with financial results withheld from output and model. It is separate from the offline authorization and negative security tests above. No live inference was rerun during finalization.

### Unverified live attack scenarios

Cross-customer requests, unknown tools, identity/permission overrides, chain attempts, and secret-export attempts have been tested offline with mocks, not verified as live model attacks. The authorized live result does not establish that a live model attempted an attack or that a live unauthorized tool request was denied. No general attack-resistance, authentication, or production-readiness claim is made.

## Limitations and review items

Finalization checks on November 4, 2026: the full offline suite passed all 264 tests in 0.39 seconds outside the sandbox. `pip check` found no broken requirements, and `git diff --check` passed. The existing Starlette/HTTPX deprecation and pip disabled-cache warnings remained. No application behavior or dependencies were changed during finalization.

- Fixture identity objects are trusted application context, not authenticated service credentials. Arbitrary local Python code can construct them or access module internals.
- The static customer-to-caller mapping is trusted policy code. Future policy additions and authentication integration need separate review.
- The dummy sentinel guard is exact-match only, not general detection of unknown/encoded secrets. No real secrets may be introduced.
- Tool result bounds are applied before return; this small in-memory fixture design does not establish resource bounds for a future database or large dataset.
- No network tools, public agent endpoints, multi-step autonomy, real data, credentials, audit integration, or Wazuh changes are implemented.
- Ollama does not authenticate local clients in this lab configuration. No production-ready service identity or secrets-management integration exists. Absolute deadline and Starlette/HTTPX deprecation limitations remain unresolved. ADR-0004 is Accepted for the implemented fixture-based framework only.
