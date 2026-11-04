# Reproducing the telemetry and detection lab

The repository publishes application code, pinned requirements, offline tests, rules, sample events, configuration examples, and sanitized indexed-alert metadata. Owner-private configuration, credentials, backups, and runtime logs are intentionally excluded. Nothing in this guide grants approval to change an existing deployment.

## Offline reproduction

From your clone with the existing Python virtual environment and repository requirements installed:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m app.telemetry_demo
.venv/bin/python -m integrations.wazuh.correlation_retest
```

The telemetry demonstration performs one authorized read and five denied operations; storage is disabled. The correlation command prints a test plan without Docker or inference. Neither requires credentials, private configuration, or live Ollama. Tests use mocks; they do not reproduce live Wazuh ingestion.

To generate local JSONL explicitly, use the following command **only when test traffic is approved**. An already installed collector will ingest newly appended events:

```bash
.venv/bin/python -m app.telemetry_demo --log-file local/telemetry/security-events.jsonl
```

Expect six schema-valid events, restrictive directory/file modes 0700/0600, and no financial payloads. `local/` is Git-ignored. Preserve the 1 MiB cap; do not truncate an active log or bypass enabled telemetry failures.

## Own Wazuh 4.14.9 environment

1. Use your own authorized Wazuh deployment and its existing access mechanism. No credentials are shipped or needed from the owner. Full integration requires authorized local Docker/manager access; indexed-alert verification requires your own existing read-only indexer access. Do not enable anonymous access for reproduction.
2. Review [COLLECTION-PLAN.md](COLLECTION-PLAN.md) for exact paths, private backup/config-copy creation, JSON localfile stanza, read-only mount, manager-only recreation, collection verification, and rollback. Adapt the example absolute host paths, Compose project, service/container names, and UID to your clone and deployment. The examples describe the verified owner's topology, not a universally applicable installer. Never reuse or overwrite another operator's active private configuration.
3. Review [PHASE-B-PROCEDURE.md](PHASE-B-PROCEDURE.md) for rule-ID conflict checks, separate XML installation, fresh-session logtest commands, SSH regression, and rule-only rollback. Preserve existing rules and do not replace `local_rules.xml`.
4. Back up your own current configuration privately and generate a new private startup-config copy from that baseline. Merge only the documented localfile block; never commit the resulting file. The small `localfile.example.xml` is not a complete manager configuration.
5. Under explicit deployment approval, apply only the narrow manager changes and verify health, read-only visibility, and existing detections. Generate fresh source IDs after the collector opens the file; match those exact IDs in manager alerts and indexed alert data. Export only the fields shown in the [sanitized evidence](evidence/2026-11-04-end-to-end-alerts.json).

Expected denial rules are 100602/7, 100603/5, 100604/7, 100605/5, and 100606/4; the fifth same-service denial may instead match 100610/10. Do not copy old evidence IDs as proof of a new run. Dashboard UI inspection and correlation expiration remain unverified. Use the full collection rollback to restore the prior manager model/configuration; removing AI rules alone does not remove collection mounts. Do not change unrelated services.
