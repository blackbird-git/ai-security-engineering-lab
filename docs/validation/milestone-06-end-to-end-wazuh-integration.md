# Milestone 6: End-to-end application security event integration

- Date: November 4, 2026
- Status: Application JSONL collection, manager alerts, and existing-indexer delivery verified; integration retained
- Scope: Wazuh 4.14.9 manager only; existing indexer queried read-only
- Decision: [ADR-0005](../security-decisions/ADR-0005-security-telemetry.md) is Accepted for the implemented scope
- Sanitized evidence: [five indexed alerts](../../integrations/wazuh/evidence/2026-11-04-end-to-end-alerts.json)
- Reviewed plan: [COLLECTION-PLAN.md](../../integrations/wazuh/COLLECTION-PLAN.md)

## Approved changes and preflight

The owner explicitly approved a separate AI rule file, a dedicated read-only telemetry bind, private manager configuration, manager-only recreation/restart, actual synthetic application events, indexed-alert verification, and rollback on failure. No indexer, dashboard, endpoint, SIEM source, Compose source, credentials, public network exposure, or unrelated repository change was authorized or performed.

Before changing anything, verified manager core health, AI active/staging file absence, no rule-ID conflicts, telemetry permissions, and unchanged baseline checksums. Privately compared the effective Compose model to the running manager: image, explicitly configured environment values, ports, networks, and startup config matched. Current effective and startup configs matched byte-for-byte. XML and sanitized samples passed local validation.

Private recoverable backup, mode 0700 and Git-ignored:

```text
local/<private-backup>/
```

Backed up effective/startup config, all custom rules, container/model metadata, baseline health/checksums, and unchanged SIEM source checksums. Private metadata can contain existing credentials and is not publication evidence. No sensitive config contents were printed.

## Actual implementation

1. Created `local/wazuh-collection/ossec.conf`, mode 0600 under a 0700 private directory, from the effective baseline. Inserted only the approved JSON localfile stanza for `/var/log/ai-security/security-events.jsonl`; removing that exact block reconstructs the baseline byte-for-byte.
2. Rendered and validated the original base Compose model plus `integrations/wazuh/compose.collection.example.yml`. Only the manager's new telemetry bind and replacement private startup-config bind differed. All nonmanager services and other manager settings/mounts remained equivalent.
3. Recreated **only** service `wazuh.manager`, with `--no-deps --no-build --pull never --force-recreate`. Persistent named volumes retained their names; no volumes were deleted. Indexer, dashboard, and endpoint start times remained unchanged.
4. Verified manager health; analysisd/logcollector configuration tests exited 0; telemetry was readable inside the manager, content hash matched the host, bind was read-only, source directory remained 0700 and file 0600.
5. Installed `/var/ossec/etc/rules/ai_security_rules.xml` separately, `wazuh:wazuh` / 0660. Existing `local_rules.xml` was never overwritten. A manager-only restart activated the new rules while retaining collection mounts/configuration.
6. Fresh-session logtest assertions passed for grouping rule 100600/0 and individual rules 100602/7, 100603/5, 100604/7, 100605/5, and 100606/4. SSH 100001/5/sshd passed after rule activation and again during final verification.

Read-only telemetry mount:

```text
Host:      /home/ilyam/ai-security-engineering-lab/local/telemetry
Container: /var/log/ai-security
RW:        false
```

Private config source `/home/ilyam/ai-security-engineering-lab/local/wazuh-collection/ossec.conf` is also mounted read-only at `/wazuh-config-mount/etc/ossec.conf`. Existing startup behavior copies it to effective `/var/ossec/etc/ossec.conf`. Use the same override on future manager recreations; base-only recreation removes this integration. No endpoint collector was modified.

## Real application event generation and observed alerts

After confirming the collector startup message for the mounted path, executed:

```bash
.venv/bin/python -m app.telemetry_demo --log-file local/telemetry/security-events.jsonl
```

The actual Python authorization workflow allowed its own-customer read and denied cross-customer, unknown-tool, identity-override, service-permission, and malformed requests. It appended six schema-valid events at source offset 1769. Model proposals were fixed offline fixtures; no live LLM attack or inference call was involved. The security decisions and resulting collection/alerts were real application/SIEM behavior.

The allowed event ID was `c3337c44-31f3-4f42-8d77-085e2c5b7353`. It is level 0 and was not expected in alerts; no claim is made that its absence from alerts proves ingestion. The five fresh denied-event IDs below were matched exactly in the manager's actual `alerts.json` **and** the existing indexer:

| Application denial reason | Request/correlation ID | Actual rule | Alert level |
| --- | --- | --- | --- |
| `CUSTOMER_SCOPE_DENIED` | `dfea0b27-96e4-49a6-8663-4f7783103ebe` | 100602 | 7 |
| `UNKNOWN_TOOL` | `63a2d6c8-1003-402d-b7d8-9d11b225428b` | 100603 | 5 |
| `IDENTITY_OVERRIDE` | `902be22f-55b3-4df4-a04f-94feefd0e6f6` | 100604 | 7 |
| `SERVICE_PERMISSION_DENIED` | `9aca06f8-2558-47e2-bc63-d156263249fc` | 100605 | 5 |
| `MALFORMED_REQUEST` | `2d37605a-872e-444d-b191-d1837e2ee5c1` | 100610 | 10 |

All five detection timestamps were `2026-11-04T19:55:06.488+0000`, event type `tool_authorization`, outcome `denied`, manager-local agent ID `000`, location `/var/log/ai-security/security-events.jsonl`. All indexed matches were in `wazuh-alerts-4.x-2026.11.04`. The final malformed event matched repeated-failure rule 100610 instead of individual rule 100606 because the five same-service denials arrived together; 100606 separately passed fresh-session logtest. This is expected correlation behavior, not a missing event.

Indexer verification used a read-only HTTPS `_search` restricted to these exact request IDs, with existing manager TLS/credentials kept only in memory. Matching source fields were restricted and then exported through an exact allowlist. No indexer setting, role, credential, container, or dashboard configuration changed. Normal existing Filebeat delivery indexed the alerts. Dashboard UI browsing was not performed; visibility was proven through indexed Wazuh alert data.

Public evidence includes event type, request ID, source/detection times, fixed reason, pseudonymous service, normalized tool, rule ID/level, location, agent ID, and index. It excludes full logs, raw model content, financial records/balances, names, credentials, tokens, and sensitive configuration. A tool identifier such as `get_customer_transactions` is metadata, not transaction data.

## Final checksums and preserved configuration

| File | Before | After |
| --- | --- | --- |
| `local_rules.xml` | `991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4` | `991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4` |
| Effective `ossec.conf` | `b137a003c617aee4a980e9eb132ced34c746a7807089a67a107dbbae74518fce` | `00e4951603cd6a879282b87197aba242aebbe29d5b4601ea37ab0cb1c330cb4f` |

The configuration hash changes intentionally for the single collection block; removing it reproduces the original bytes. Installed AI XML SHA-256 matches the reviewed artifact: `447f2f785e009a6896f4e213bb8d9f403fcbe6c042c43cb7f2020855211a6eaa`. Original manager environment entries, image, network names, published ports, existing named volumes, and SIEM source-file hashes were preserved. Compose reordered environment entries, so an initial order-sensitive check paused; comparing the complete sorted entries confirmed no value or duplicate-entry drift. No setting was relaxed or bypassed.

Final manager state: all ten baseline core daemons running; analysisd/logcollector tests pass; telemetry readable/read-only; AI rules installed; SSH 100001 passes. Optional inactive daemons remain as in the baseline. No required integration validation failed and rollback was not needed. The reviewed backup and manager-only rollback procedure remain available.

## Automated validation and remaining limitations

All **328 repository tests passed** in 0.85 seconds outside the sandbox due to the known health TestClient hang. `pip check` found no broken requirements; `git diff --check` passed. Existing Starlette/HTTPX deprecation and pip disabled-cache warnings remained. Public evidence passed exact-field/UUID/timestamp checks and documentation links were verified. No packages were installed, and no commits or pushes were performed.

This validates current application-to-file-to-manager-to-indexer delivery for five fresh denials and within-window correlation in actual collection. **Correlation expiration remains unverified**, not a confirmed rule defect. The prior unsynchronized test and later cleanup-adapter error are documented in [Investigation 002](../investigations/002-wazuh-correlation-expiry.md); the corrected synchronized expiry harness was not rerun in this integration task. No broad model attack-resistance, production identity, durable audit delivery, or SOC production-readiness claim is made.

The 1 MiB file cap, lack of supervised rotation, restart loss/duplication risks, exact-match dummy-secret guard, fixture identity limitations, unsigned source events, and unauthenticated local inference remain. An application writer success is not an acknowledgment from Wazuh. Runtime operations must preserve the approved override/private config and restrictive permissions. No external service exposure was added. No commits or pushes were performed.

## Final milestone review

The owner confirmed all five indexed alerts, rule 100610 at level 10, preserved SSH detection, healthy manager, and retained integration. ADR-0005 is Accepted for the implemented scope. Final pre-commit validation: **328 tests passed** in 0.43 seconds outside the sandbox, with one existing Starlette/HTTPX deprecation warning; `pip check` found no broken requirements (existing disabled-cache warning); whitespace checks passed. No application behavior, dependencies, running integration, or other repository was changed during finalization. The sandbox test attempt stalled at the known TestClient boundary; no root cause is claimed.

Public files were reviewed for credentials, tokens, real customer information, private backup identifiers/configuration, Docker secrets, and unintended artifacts. Backup instance paths were replaced with placeholders; runtime logs, private configuration, backups, and virtual environments remain ignored. The [concise investigation](../investigations/003-ai-agent-authorization-detection.md) and [portable reproduction guide](../../integrations/wazuh/REPRODUCE.md) link the evidence without publishing private files.
