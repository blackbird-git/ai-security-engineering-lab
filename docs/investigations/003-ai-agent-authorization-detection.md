# Investigation 003: AI agent authorization detection

- Date: November 4, 2026
- Outcome: Five application denial events collected and indexed; implemented Milestone 6 scope complete
- Decision: [ADR-0005, Accepted](../security-decisions/ADR-0005-security-telemetry.md)
- Evidence: [sanitized indexed-alert metadata](../../integrations/wazuh/evidence/2026-11-04-end-to-end-alerts.json)

## Objective and environment

Determine whether real Python authorization decisions produce identifiable Wazuh alerts without exporting financial data or model content. This educational lab uses Python, local Ollama, synthetic financial fixtures, scoped read-only tools, and Wazuh 4.14.9. FastAPI remains health-only; fixture service identities are not real authentication.

The verified path was Python authorization → bounded JSONL → read-only manager bind → JSON logcollector → separate AI rules → manager alerts → existing indexer. Only the manager integration changed during the previously approved deployment. The indexer was queried read-only; dashboard and endpoint configurations were untouched. This final documentation review did not modify the running integration.

## Detection scenario and event fields

The offline telemetry CLI submitted six fixed proposals through the actual protected dispatcher: one authorized read and five denials (customer scope, unknown tool, identity override, service permission, malformed request). Model proposals were fixtures, not live inference. Authorization decisions, collection, and indexed alerts were real observed behavior.

Schema 1.0 contains UTC timestamp, schema version, event type, outcome, severity, UUID request/correlation ID, pseudonymous service ID, normalized tool ID, and finite denial reason. Python generates these fields at authorization gates; the LLM cannot assert an event outcome. Events exclude prompts, model responses, customer identifiers/names, financial records, secrets, and credentials. An identity-override field is an indicator, not proof of successful prompt injection.

## Triggered rules and verified correlation IDs

| Denial reason | Request/correlation ID | Wazuh rule | Level |
| --- | --- | --- | --- |
| `CUSTOMER_SCOPE_DENIED` | `dfea0b27-96e4-49a6-8663-4f7783103ebe` | 100602 | 7 |
| `UNKNOWN_TOOL` | `63a2d6c8-1003-402d-b7d8-9d11b225428b` | 100603 | 5 |
| `IDENTITY_OVERRIDE` | `902be22f-55b3-4df4-a04f-94feefd0e6f6` | 100604 | 7 |
| `SERVICE_PERMISSION_DENIED` | `9aca06f8-2558-47e2-bc63-d156263249fc` | 100605 | 5 |
| `MALFORMED_REQUEST` | `2d37605a-872e-444d-b191-d1837e2ee5c1` | 100610 | 10 |

The fifth same-service denial matched correlation rule 100610 instead of individual malformed-request rule 100606. Rule 100606 separately passed fresh-session logtest. The allowed event was not expected to alert; absence of an alert does not establish its collection.

## Evidence collection methodology

After verifying collection startup, the application appended fresh events using:

```bash
.venv/bin/python -m app.telemetry_demo --log-file local/telemetry/security-events.jsonl
```

Only newly appended source IDs were matched against manager `alerts.json` and a read-only index search. All five denials matched the exact IDs, expected source location `/var/log/ai-security/security-events.jsonl`, local agent `000`, and index `wazuh-alerts-4.x-2026.11.04`. Source timestamps were `2026-11-04T19:55:05.433Z`; detection timestamps were `2026-11-04T19:55:06.488+0000`. These timestamps record this run, not a latency guarantee.

Published evidence uses an exact metadata allowlist and omits full logs, configuration, credentials, and backups. The [detailed validation record](../validation/milestone-06-end-to-end-wazuh-integration.md) documents checksums, preserved SSH rule 100001, healthy manager state, and the retained integration. Automated testing is separate evidence: 328 tests passed; tests use offline fixtures and do not establish live ingestion by themselves.

## Analysis and outcome

All five fresh denial events generated indexed alerts. The repeated-failure rule reached level 10 for five same-service failures inside the window, including mixed denial types. Existing SSH rule 100001 remained functional and `local_rules.xml` was unchanged. The approved integration remains installed. These results establish the tested authorization-to-detection path; they do not show a successful model compromise or financial disclosure.

## Limitations and reproduction

Correlation expiration remains unverified; the earlier mismatch is not a confirmed rule defect ([Investigation 002](002-wazuh-correlation-expiry.md)). Dashboard UI was not inspected. Supervised rotation is pending; the writer caps storage at 1 MiB and enabled audit failures deny authorized reads. Events are unsigned and local privileged processes can fabricate them. Fixture identities are not real authentication, dummy-secret protection is exact-match only, and local Ollama does not authenticate clients. All financial data is synthetic. This is not a production SOC deployment.

The [reproduction guide](../../integrations/wazuh/REPRODUCE.md) requires no owner-private files or credentials and links the reviewed deployment and rollback instructions for a reader's own authorized Wazuh environment. Live correlation expiry and ongoing retention require further validation.
