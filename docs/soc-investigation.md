# Human-reviewed synthetic SOC investigation

The flow is reviewed sanitized evidence → strict validation → one mock/local model proposal → Python schema/reference checks → Draft → explicit trusted approval or rejection. Only Approved can create a local report. FastAPI remains health-only. Neither the model nor a report can call a tool or execute follow-up.

## Evidence contract

`app.investigation_evidence.load_evidence()` reads only [the published five-alert artifact](../integrations/wazuh/evidence/2026-11-04-end-to-end-alerts.json). Its existing exact structural contract is recognized as `sanitized-indexed-alerts-v1`; it is not the application JSONL schema and has no version field in the source file. The reader checks all metadata and record keys/types, UUIDv4 correlations, UTC timestamp syntax/calendar values, detection not preceding event, the expected rule/reason/level/tool combinations, and unique identifiers. It permits only the five reviewed synthetic indexed authorization denials, no arbitrary log content.

Total input is capped at 16,384 bytes, each serialized record at 1,024 bytes, and the count at exactly five. Invalid Unicode, duplicate JSON keys, NaN/constants, unexpected schema/fields, and modified source bytes are rejected before inference. The reviewed SHA-256 is pinned in code. Even a well-formed replacement correlation ID fails the fingerprint check. Whitespace-only source edits also require reviewed fingerprint maintenance. This narrow fixture reader is intentionally not a general-purpose alert import service.

## Compact draft contract and citations

The model output is one JSON object of at most 4,096 UTF-8 bytes:

```json
{
  "incident_summary": "all",
  "timeline": "all",
  "relevant_detection_rules": "all",
  "observed_security_events": "all",
  "evidence_references": ["E1", "E2", "E3", "E4", "E5"],
  "potential_impact": "not_established",
  "recommended_analyst_follow_up": "review_evidence",
  "uncertainties_and_limitations": "lab_limits"
}
```

`all` explicitly attaches each factual section to the shared validated evidence list. Every reference must occur exactly once, with no unknown or missing aliases. `review_expiry` is the only alternative follow-up choice. The aliases map to immutable validated correlation IDs; unsupported rules or fabricated event IDs cannot enter through another field. Python renders section text, rule numbers, timeline values, and citations directly from evidence, not from model assertions. All observations cite both alias and correlation ID; impact and limitations cite the shared evidence context. The source fingerprint and schema are recorded in the report.

The proposal can reorder references and choose a bounded follow-up, but cannot supply free-form findings, arbitrary recommendations, or claims of compromise. This is intentionally constrained AI assistance. Missing sections, free text/code fences, duplicate keys, secrets, actions, approval fields, and unrestricted remediation requests fail validation. Rejected response text and underlying exception details are never logged or printed.

## Offline demonstration

From the repository root with the existing environment:

```bash
# Mock generation, evidence validation, rendered Draft; writes nothing
.venv/bin/python -m app.soc_investigation
# Display draft, then require exact APPROVE or REJECT from the local reviewer
.venv/bin/python -m app.soc_investigation --review
```

For reproducible **trusted scripted decisions** in this synthetic demo:

```bash
printf 'REJECT\n' | .venv/bin/python -m app.soc_investigation --review
printf 'APPROVE\n' | .venv/bin/python -m app.soc_investigation --review
```

Expected: Draft and Rejected publish nothing. Approved creates a UUID-named Markdown report only in `local/investigations/approved/` (0700 directories, 0600 file). Existing files are not overwritten. The complete staged file is published only after the approval check; partial writes fail and are cleaned up. A rejected session cannot be reapproved. This stores a local approved report; it never publishes to GitHub or executes recommendations. Runtime reports remain ignored and contain only validated security metadata/templates.

## Optional local inference, disabled by default

```bash
.venv/bin/python -m app.soc_investigation --run-live --review
```

This makes one call to the existing fixed `qwen3:4b-instruct` client at `127.0.0.1:11434`; it does not query Wazuh. It still requires valid structured output and separate review. Live inference was not executed during implementation; the owner subsequently verified a successful five-alert, eight-section draft and explicit approval, recorded in the validation document. The unchanged 128-token limit can truncate even compact JSON; invalid or incomplete generation fails closed without automatic repair/retry. That single observed success does not establish general live generation reliability.

## Security limits

Human approval relies on the trusted local application/terminal, not authenticated reviewer identities. A malicious local process can change the application, evidence hash, review state, or stored report; this is not a production approval system. There is no production service identity, tamper-resistant audit trail, report-retention/count quota, or independent evidence attestation. Snapshot freshness/provenance still requires analyst judgment. Unauthenticated local Ollama and per-read rather than absolute deadlines remain. No live model attack resistance was established. All data is synthetic; this is not a production SOC deployment.

[Investigation 003](investigations/003-ai-agent-authorization-detection.md) supplies the earlier verified collection context, including unverified correlation expiration, uninspected dashboard UI, and pending supervised rotation. See [ADR-0007 (Accepted)](security-decisions/ADR-0007-human-reviewed-investigations.md) for review assumptions and [validation](validation/milestone-08-soc-investigation.md) for actual executed tests/demonstrations.

Event timestamps are reproduced verbatim from evidence. E1–E5 and display order are references, not a chronology among same-timestamp events. No order beyond the recorded timestamps is inferred.
