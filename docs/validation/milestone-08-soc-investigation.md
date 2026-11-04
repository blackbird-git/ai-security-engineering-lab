# Milestone 8: Human-reviewed AI-assisted investigation validation

- Date: November 4, 2026
- Status: Complete for the implemented synthetic evidence-validation and human-review workflow; owner-verified live run succeeded
- Decision: [ADR-0007 (Accepted)](../security-decisions/ADR-0007-human-reviewed-investigations.md)
- Reproduction: [usage guide](../soc-investigation.md)

## Automated evidence

| Command | Observed result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **406 passed**, including the original 328 tests and 78 new investigation tests; 0.53 seconds outside the sandbox; one existing Starlette/HTTPX deprecation warning |
| `.venv/bin/python -m pip check` | No broken requirements found; existing disabled-cache permissions warning |
| `git diff --check` | Passed |

New tests use deterministic mock generation and block network connections. They cover reviewed schema/hash ingestion, types, UUIDs, UTC timestamps and ordering, rule consistency, duplicates, file/record/response limits, unknown fields, secrets and financial text, evidence prompt injection, fabricated correlations/references/rules, malformed model output, denied remediation requests, model-generated approval/status, exact trusted decision types, terminal rejection, no publication before approval, private storage, symlink rejection, and short/failed-write cleanup. The live CLI branch is tested with a fake client only. No packages or application dependencies were changed.

Every accepted draft uses all reviewed evidence IDs. Python renders factual findings from immutable validated evidence and controlled templates; it does not copy arbitrary model narrative or accept model-provided commands. Approval fields in model JSON fail schema validation. A trusted local decision is required separately; negative tests verify Draft/Rejected cannot call `publish()` successfully, and rejection cannot transition to approval.

## Executed offline demonstrations

Executed the following commands with mock model responses and the existing sanitized five-alert artifact:

```bash
.venv/bin/python -m app.soc_investigation
printf 'REJECT\n' | .venv/bin/python -m app.soc_investigation --review
printf 'APPROVE\n' | .venv/bin/python -m app.soc_investigation --review
```

Observed respectively:

- `Outcome: Draft; nothing published.`
- `Outcome: Rejected; nothing published.`
- `Outcome: Approved; stored at local/investigations/approved/<application-generated-uuid>.md`.

Each run ingested and validated five reviewed alerts, rendered eight sections with citations, and displayed the human approval requirement. The trusted shell supplied the approval/rejection decision; this demonstrates the application gate, not real reviewer authentication. The approved report is local, synthetic, owner-only, and Git-ignored; no raw prompts/responses or financial records were printed or stored. These commands do not append telemetry or interact with Wazuh. A final rerun after compacting the proposal schema confirmed the same outcomes.

## Prior live evidence versus current model validation

The input [sanitized indexed-alert artifact](../../integrations/wazuh/evidence/2026-11-04-end-to-end-alerts.json) records previously verified Wazuh detections. Its provenance and exact correlations are described in [Investigation 003](../investigations/003-ai-agent-authorization-detection.md). Current offline analysis does not revalidate that deployment, produce new SIEM alerts, or establish actual live model reasoning. The artifact's exact bytes are pinned; the hash is a reviewed-fixture integrity check, not an independent signature or guarantee against a compromised maintainer.

Implementation validation used no live inference; the separate owner-verified live result is recorded below. No external API, paid service, Wazuh/Docker change, public endpoint, or autonomous remediation was involved. Mock results remain distinct from the live observation.

## Remaining work and limitations

ADR-0007 is Accepted for the implemented workflow, supported by offline tests and the owner-verified live run. Future authenticated reviewer/audit/retention designs and broader live reliability testing remain. The existing health-only API and customer/tool authorization controls are preserved. Host/application/reviewer code is trusted; local enums/private attributes are not authentication or capabilities against arbitrary Python execution. Approved files can be edited by their owner and have no approval signature or transactional audit backend. Narrative freedom is deliberately limited to prevent unsupported findings and sensitive free-text leakage. Correlation expiry, dashboard inspection, supervised log rotation, fixture identities, and synthetic-only lab limitations remain; no production SOC readiness or generalized prompt-injection resistance is claimed. No commit or push was performed.

## Owner-verified live investigation and approval

The owner executed:

```bash
.venv/bin/python -m app.soc_investigation --run-live --review
```

The owner verified these results:

- Five sanitized Wazuh alerts validated.
- Local Ollama generation completed.
- An eight-section investigation draft was produced.
- Findings cited evidence E1–E5.
- The report distinguished denied actions from successful attacks or disclosure.
- No autonomous remediation occurred.
- The owner explicitly entered `APPROVE`.
- The approved report was stored under the ignored `local/investigations/approved/` directory.

This is owner-reported live evidence, separate from deterministic offline tests. The private approved report is not published or read into repository evidence. No live run was repeated during finalization, and no run timestamp or private report filename was supplied for publication. This one successful run does not establish general model reliability.

### Recorded event times and ordering limits

All five source events retain `2026-11-04T19:55:05.433Z`; all five detection timestamps retain `2026-11-04T19:55:06.488+0000`. These are the prior Wazuh evidence timestamps, not timestamps of the live investigation/approval. E1–E5 are artifact references, not chronological sequence numbers. The displayed list/model ordering does not establish order among events sharing those timestamps. No finer ordering or causal sequence is inferred, and the original artifact/hash remains unchanged.

### Accepted scope limitations

Reviewer identity is fixture-based and trusts the local reviewer channel; there is no authenticated reviewer service, tamper-resistant approval audit trail, or automated retention management. Evidence is synthetic-only. There is no production SOC integration and no autonomous remediation. The existing token cap, unauthenticated local inference, host trust, and earlier SIEM validation limits remain.

## Final pre-commit checks

Finalization reran the full suite: **406 tests passed** in 0.57 seconds with the existing Starlette/HTTPX warning. All **13 CI workflow-policy checks passed**; dependency consistency and whitespace checks passed. Gitleaks scanned reachable history and nonignored source with no leaks found. Approved reports and other `local/` runtime artifacts remain ignored and are excluded from the publication set. No live inference, infrastructure changes, or private-report publication occurred during finalization.
