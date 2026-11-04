# ADR-0005: Structured authorization telemetry and Wazuh artifacts

- Status: Accepted
- Date: 2026-11-04
- Scope: Implemented application telemetry, manager-local JSONL collection, separate AI rules, and verified indexed alerts in the synthetic lab

## Context and decision

The scoped agent dispatcher already makes deterministic service/tool/customer authorization decisions. Emit telemetry at those decision points rather than asking an LLM whether an attack occurred. Preserve the protected reader, single-step orchestration, fixed local inference client, and health-only FastAPI surface. Acceptance records the separately owner-approved integration; it does not authorize further Wazuh changes, public endpoints, additional tools, or external connections.

`SecurityTelemetry` builds an exact, bounded JSON schema. `execute_tool` accepts an optional trusted telemetry context; `run_agent` forwards it. Neither the model nor its proposal may supply identity, correlation ID, event fields, or a telemetry file path. The existing default constructs and validates events in memory, with no filesystem writes. An explicitly supplied `JsonlWriter` enables persistence.

## Schema version 1.0

One JSON object per line, with exactly one top-level `ai_security` object and these exact string fields:

| Field | Contract |
| --- | --- |
| `timestamp` | Application-generated UTC timestamp, ISO 8601 with milliseconds and `Z` |
| `schema_version` | `1.0` |
| `event_type` | `tool_authorization` or `tool_result` |
| `outcome` | `allowed` or `denied` |
| `severity` | `info` for allowed, `medium` for denied; distinct from Wazuh rule levels |
| `request_id` | Application-generated canonical UUIDv4, or validated trusted caller context; shared across events for one tool invocation |
| `service_id` | Fixed pseudonymous alias `service-01` through `service-04`; other/malformed services become `service-unknown` |
| `tool_id` | One of the two allowlisted tools; `unknown` for unknown string names, `none` when not safely available |
| `denial_reason` | Fixed reason code; `NONE` for an allowed decision |

Reason codes are `CUSTOMER_SCOPE_DENIED`, `UNKNOWN_TOOL`, `IDENTITY_OVERRIDE`, `SERVICE_PERMISSION_DENIED`, `MALFORMED_REQUEST`, `UNKNOWN_SERVICE`, and `RESULT_REJECTED`. Validation rejects extra fields, arbitrary values, inconsistent outcome/severity, invalid IDs/timestamps, and lines exceeding 1,024 UTF-8 bytes including newline. No free-text message field exists. Exact fixture aliasing is data minimization, not cryptographic anonymization.

An allowed authorization event is emitted before the read and means **policy permitted a read**, not proof the read completed or a result was delivered. A later reader/export failure emits a separate `tool_result` denial with `RESULT_REJECTED` under the same request ID. Inference failures before tool dispatch do not generate authorization events. Multiple faults are reported by the first validation gate; this is not exhaustive attack classification. An invalid trusted request ID is denied without exporting it.

## Privacy and trust boundary

Never export raw prompts, responses, arguments, financial records or balances, transaction details, customer IDs/names, authentication tokens, credentials, or secrets. Unknown model-controlled tool names and supplied service strings are not copied; only finite aliases are emitted. Known tool names are normalized through the allowlist. Identity override events report an actual rejected field in a parsed proposal, not a successful injection. Suspicious prose is not inspected for attack claims; it is an invalid proposal if it cannot meet the tool schema.

Trusted Python determines reasons, timestamps, aliases, and outcomes. This cannot prevent a compromised Python process or local operator from fabricating files or calling the telemetry module directly. It also cannot attest that a live LLM produced a request. Wazuh/collectors must treat logs as untrusted input and protect their source and transport independently. Events are not cryptographically signed.

## Opt-in bounded local file and failure policy

Only explicit configuration enables appending to a simple lowercase `.jsonl` filename directly under this repository's `local/telemetry/`. The CLI accepts `--log-file`; there is no model-controlled configuration or environment-based auto-enablement. The whole `local/` directory is already ignored by Git.

The Linux writer traverses fixed repository-relative directories using directory descriptors, rejects symlinks in the local directories/final file, and rejects nonregular, multiply linked, foreign-owned, or group/world-accessible files. Newly created directories use mode 0700 and files 0600. It uses a nonblocking advisory lock, checks the file cap while locked, and appends one serialized line. The maximum file size is 1 MiB; there is no automatic rotation or overwrite. Cooperating writers honor the lock; this does not sandbox privileged or hostile local processes.

When telemetry is explicitly enabled, a write/configuration/serialization/lock/capacity failure cannot grant access: authorized operations are denied **before data access** if the authorization event cannot be stored. Denied requests remain denied even if their denial event is lost. If result rejection occurs after an allowed read, data remains withheld regardless of whether its rejection event is stored. Errors remain fixed sanitized `ToolDenied` messages. The CLI reports only fixed storage status and exits nonzero on persistence failure. This is deliberately fail-closed for enabled audit storage, accepting availability loss at capacity or on I/O failure.

Disabled persistence permits existing operations with in-memory schema validation and no logs. A successful append is not guaranteed durable against power loss: there is no `fsync` or transactional audit backend. Partial writes can leave an incomplete final line; access is denied, but no rollback or recovery is attempted. Denial-event loss cannot be reported through the failed sink. These limitations need resolution before ongoing collection or production use.

## Wazuh artifacts and validation

Prepare JSON `localfile` collection and custom rules in [integrations/wazuh](../../integrations/wazuh/README.md). Rules recognize the schema, individual reasons, and a repeated-failure group keyed by service pseudonym. They intentionally describe authorization failures and possible indicators, never confirmed successful attacks. Rule IDs, levels, frequency behavior, JSON dynamic-field decoding, collector permissions, and host/container paths require review against Wazuh 4.14.9 before deployment.

Tests and the offline CLI exercise real application decisions using mock model proposals; they validate event privacy, correlation, bounded storage, logging failures, JSON, and XML structure. Phase A does not install rules, touch the Wazuh repository, run `wazuh-logtest`, send events over the network, or claim detection effectiveness. [Validation evidence](../validation/milestone-06-phase-a-security-telemetry.md) distinguishes these boundaries. ADR-0005 was Proposed during this historical phase.

## Subsequent approved Phase B trial

A later manager-only installation/test was explicitly authorized. Individual detection and several correlation/negative cases matched expectations, but a real-wait expiry expectation failed in a harness without synchronized engine-processing acknowledgments. The AI file was removed and manager health, existing configuration, and SSH detection restored/verified. See [Phase B actual evidence](../validation/milestone-06-phase-b-wazuh-rule-validation.md). Root cause remains unresolved; no general engine defect or successful deployment is claimed. ADR status was Proposed during that trial.

## Later approved collection implementation

The owner separately approved deployment of manager-local JSON collection, a narrow read-only telemetry bind, private manager startup configuration, and the reviewed separate AI rule XML. Five fresh application denial IDs were verified in real manager alerts and the existing Wazuh alert index; the integration remains installed. See [end-to-end evidence](../validation/milestone-06-end-to-end-wazuh-integration.md). Earlier rule-only rollback history remains documented. Expiry remains unverified; this decision is now Accepted only for the implemented and tested scope; successful collection is not evidence of production readiness or universal detection effectiveness.

## Acceptance limits

Acceptance covers the implemented telemetry and detection framework, supported by [Investigation 003](../investigations/003-ai-agent-authorization-detection.md) and its sanitized indexed-alert evidence. Correlation expiration is not verified; dashboard UI inspection and supervised log rotation remain pending. Fixture identities are not real authentication; only synthetic financial data is permitted. This is an educational lab, not a production SOC deployment. No production service identity, secrets-management, durable audit-delivery, or general prompt-injection-resistance guarantee is established.
