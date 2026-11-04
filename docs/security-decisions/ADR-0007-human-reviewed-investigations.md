# ADR-0007: Evidence-grounded investigation drafts with human approval

- Status: Accepted
- Date: 2026-11-04
- Scope: Internal synthetic evidence reader, bounded draft proposal, local review and storage

## Decision and trust boundaries

Use the existing sanitized indexed-alert artifact rather than a live Wazuh connection or raw log reader. `app.investigation_evidence` accepts only its reviewed legacy envelope/record schema and exact SHA-256. Normalize it as `sanitized-indexed-alerts-v1` in memory; the original artifact has no explicit schema-version field and is unchanged. Reject extra fields, duplicate JSON keys, nonstandard constants, invalid types/UUIDv4/timestamps, inconsistent rule/reason/level combinations, duplicate correlations, oversized records, and changed artifact bytes. A new evidence source/version requires review and a new explicit contract, not a caller-selected path or automatic trust.

Validate the complete artifact before inference. Pass only evidence aliases, fixed reasons, and rule numbers to one generation callable. The opt-in live branch uses the existing `OllamaClient`, unchanged fixed localhost destination/model, timeouts, completion checks, 2,000-character prompt cap, and 128-token setting. Do not provide the model tools, credentials, financial records, live SIEM access, arbitrary file access, or report-writing capabilities.

The model proposes a compact eight-field JSON draft using a controlled vocabulary. Python validates the full response, requires all five known evidence references, rejects extra fields/actions/status, and renders eight report sections from validated evidence and fixed narrative templates. Each factual observation includes an evidence alias and actual correlation UUID. Impact must remain `not_established`; follow-up is limited to manual evidence review or planning separately approved expiry validation. Model text is never copied as unrestricted prose. This deliberately limits generation to evidence organization and safe follow-up selection rather than open-ended SOC reasoning. A valid schema does not establish independent truth or model trustworthiness.

## Human approval and storage

`Investigation` starts in Draft. Only trusted application code can call `decide(Decision.APPROVE)` or `decide(Decision.REJECT)`. The model JSON cannot supply state, approval, identity, permissions, actions, or commands. Both decisions are terminal: rejected sessions cannot later be approved and neither Draft nor Rejected can publish. The CLI displays the rendered draft and requires `--review` plus exact human input `APPROVE` or `REJECT`; absence, EOF, or any other input produces no approved report. No model output is routed to the review input.

Only Approved may write under ignored `local/investigations/approved/`, using application-generated UUID filenames, private owner-only directories/files, no-symlink directory traversal, exclusive creation, a complete staged file, and an exclusive hard-link publication. I/O failures are sanitized; partial staged writes are removed rather than published as reports. No external publication or remediation exists. Approval means a local report was explicitly accepted, not that recommended follow-up was executed.

## Consequences and limitations

This boundary assumes trusted Python/host code and a trusted local reviewer channel. Python private attributes and enums are not authentication, unforgeable capabilities, or a sandbox against an operator who can edit code/files. Piped CLI input is a trusted scripted decision for reproducibility, not evidence of authenticated human identity. No production analyst identity, role separation, approval audit trail, electronic signature, signed evidence, file tamper detection after publication, retention policy, report-count quota, or durable transactional audit service exists.

Pinning the exact reviewed artifact detects changes relative to that fixture, not fabrication by a compromised maintainer or host. The workflow cannot establish provenance independently of the previously owner-verified Wazuh evidence. No arbitrary raw logs, financial fields, free-form notes, URLs, model narratives, or customer identifiers are accepted. Controlled strings prevent those channels from carrying new secrets; this is not a general secret scanner for arbitrary investigations.

One owner-verified live generation/review succeeded; other generations can still fail due to invalid JSON, instruction failure, or the existing 128-token cap. No retries, output repair, relaxed completion checks, token-limit changes, or bypass is introduced. Existing unauthenticated loopback inference and absence of absolute deadlines remain. Correlation expiration, dashboard UI, supervised rotation, fixture authentication, and synthetic-only lab limitations remain. No production SOC or general model attack-resistance claim is made.

See the [usage guide](../soc-investigation.md) and [Milestone 8 validation](../validation/milestone-08-soc-investigation.md). Accepted only for the implemented evidence-validation and human-review workflow, including the documented owner-verified live run. Reviewer identity remains fixture-based, with no authenticated reviewer service, tamper-resistant approval audit trail, automated retention management, production SOC integration, or autonomous remediation. This decision grants no Wazuh/Docker changes, public routes, external publication, or autonomous response authority.
