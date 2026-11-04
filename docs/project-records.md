# Project records and detailed limitations

This index preserves the milestone evidence, architecture decisions, and detailed limitations behind the [portfolio overview](../README.md).

## Investigations and validation

| Investigation | Supporting evidence |
| --- | --- |
| [001: Ollama generation truncation](investigations/001-ollama-generation-truncation.md) | [Internal client validation](validation/milestone-03-ollama-integration.md) |
| [002: Correlation expiration mismatch](investigations/002-wazuh-correlation-expiry.md) | [Historical Phase B tests and rollback](validation/milestone-06-phase-b-wazuh-rule-validation.md) |
| [003: Agent authorization detection](investigations/003-ai-agent-authorization-detection.md) | [End-to-end Wazuh validation](validation/milestone-06-end-to-end-wazuh-integration.md) and [sanitized indexed alerts](../integrations/wazuh/evidence/2026-11-04-end-to-end-alerts.json) |

All eight milestones are complete for their recorded scope:

| # | Completed milestone | Record |
| --- | --- | --- |
| 1 | Scope and trust boundaries | [Accepted design](security-decisions/ADR-0001-scope-and-trust-boundaries.md) |
| 2 | Health-only FastAPI baseline | [Validation](validation/milestone-02-fastapi-baseline.md) |
| 3 | Internal local Ollama client | [Validation](validation/milestone-03-ollama-integration.md) |
| 4 | Prompt injection and customer authorization | [Validation](validation/milestone-04-prompt-injection-authorization.md) |
| 5 | Scoped agent tools and fixture identities | [Validation](validation/milestone-05-scoped-agent-tools.md) |
| 6 | AI telemetry and Wazuh detections | [Validation](validation/milestone-06-end-to-end-wazuh-integration.md) |
| 7 | GitHub Actions security pipeline | [Local validation](validation/milestone-07-security-ci.md) and [verified hosted run](https://github.com/blackbird-git/ai-security-engineering-lab/actions/runs/41908231336) |
| 8 | Human-reviewed SOC investigations | [Offline and owner-verified live validation](validation/milestone-08-soc-investigation.md) |

## Security architecture decisions

All seven ADRs are Accepted for their documented scopes: [scope and trust boundaries](security-decisions/ADR-0001-scope-and-trust-boundaries.md), [local inference](security-decisions/ADR-0002-local-ollama-client.md), [synthetic data and authorization](security-decisions/ADR-0003-synthetic-data-and-authorization.md), [scoped tools and identities](security-decisions/ADR-0004-scoped-agent-tools.md), [telemetry and detection](security-decisions/ADR-0005-security-telemetry.md), [security CI](security-decisions/ADR-0006-security-ci.md), and [human-reviewed investigations](security-decisions/ADR-0007-human-reviewed-investigations.md). [AGENTS.md](../AGENTS.md) records engineering and safety standards.

## Known limitations

- Service and reviewer identities are lab fixtures, not production authentication. No authenticated reviewer service or tamper-resistant approval audit trail exists.
- Synthetic data/evidence only; SOC prose is rendered from controlled templates and validated references, not unrestricted model analysis. No autonomous remediation or production SOC integration.
- Correlation expiration is unverified; dashboard UI was not inspected. The telemetry file stops at 1 MiB; supervised rotation and automated report retention remain pending.
- Local Ollama clients are unauthenticated. The 128-token cap can truncate drafts; timeouts are not absolute deadlines. Live successes do not establish general attack resistance.
- Events/reports are unsigned and local host/application code is trusted. The evidence fingerprint checks one reviewed artifact, not independent provenance.
- Dependency pins lack hashes; runner images and Python patch versions can change. Scanning is point-in-time and cannot find every secret or vulnerability. PR/manual-trigger behavior and required-check settings remain unverified.
- Existing Starlette/HTTPX deprecation warning and sandbox TestClient hang remain documented. [Publication review](publication-security-review.md) records accepted author-metadata disclosure, retained reproduction metadata, and review limits.
