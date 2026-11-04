# Milestone 6: End-to-end collection preparation

- Date: November 4, 2026
- Status: Historical preparation record; later collection deployment and live validation are recorded in the end-to-end validation document
- Scope: AI repository artifacts and read-only Docker/Wazuh inspection
- Plan: [Exact collection/verification/rollback procedure](../../integrations/wazuh/COLLECTION-PLAN.md)

## Confirmed architecture

The existing endpoint `security-endpoint-01` is active as agent 002, but has no mount of host telemetry. The manager is local agent 000 and likewise cannot currently see the application JSONL. Manager, indexer, and dashboard images are 4.14.9. The manager Compose service is `wazuh.manager`, with base source/working directory under `../security-operations-lab/wazuh-docker/single-node`; those files were not modified.

Manager `/var/ossec/etc` and `/var/ossec/logs` are existing named volumes. The startup config bind targets `/wazuh-config-mount/etc/ossec.conf`. Read-only review of `/etc/cont-init.d/0-wazuh-init` confirms files there are copied into `/var/ossec` at startup. A persistent collection configuration therefore needs a reviewed startup source, not only a live volume edit.

Manager and endpoint logcollectors run as root/group wazuh. Docker reports seccomp/cgroupns, without a reported rootless/userns-remap mode. Host telemetry is owned by UID/GID 1000:1000 with 0700 directories and a 0600 JSONL file. Existing logcollector help confirms `-t` configuration testing. Neither collector has an AI localfile stanza. Manager AI rule XML remains absent; the rules artifact is kept separate from collection configuration.

## Selected design and changes prepared

Recommend the manager's existing local collector with a read-only bind of **only** `local/telemetry` to `/var/log/ai-security`. Reusing the endpoint would also require mount/config/recreation changes there, expanding the affected components unnecessarily for this local lab. A shared directory alone does not forward logs; manager-local collection is what reads it.

Prepared `integrations/wazuh/compose.collection.example.yml`: one added read-only telemetry bind, plus a replacement of the existing startup-config bind source with a private ignored AI-repository config copy. This keeps all SIEM repository source files unchanged. Updated `localfile.example.xml` to JSON collection at `/var/log/ai-security/security-events.jsonl`.

The plan covers private backup, exact minimal config insertion, mode/ownership preservation, manager-only recreation using `--no-deps`, read-only mount checks, analysisd/logcollector tests, SSH preservation, fresh application request-ID generation, bounded matched-alert verification, and removal of the override for rollback. It never mounts all of `local/`, which contains sensitive backups, or the repository/credentials. The private copied configuration is created only during a future approved implementation, not during preparation.

## Executed preparation checks

Docker inventory, mount metadata, Compose labels, agent inventory, selected localfile blocks, process users, startup scripts, collector help, and checksums were inspected read-only. No full environment, certificate/key contents, agent credentials, or full Wazuh config was printed.

The candidate Compose model was rendered using `docker compose config --no-interpolate --format json` with the original project directory/project name and the candidate override. Full output was captured in memory, not printed or saved. Assertions passed:

- Indexer/dashboard and all other nonmanager service definitions were identical to the base model.
- All manager settings other than volumes were identical.
- All original manager mounts except the explicitly replaced startup-config source were identical.
- Exactly one net mount was added; telemetry and private config mounts were both read-only with `create_host_path: false`.

No `up`, `restart`, `down`, volume operation, rule installation, actual logcollection configuration, or new telemetry generation occurred. Rendering does not prove runtime source readability or successful recreation.

Read-only baseline checksums:

```text
local_rules.xml: 991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4
ossec.conf:      b137a003c617aee4a980e9eb132ced34c746a7807089a67a107dbbae74518fce
```

Automated checks: all **328 tests passed** in 0.53 seconds outside the sandbox due to the existing health TestClient hang. `pip check` found no broken requirements; `git diff --check` passed. Existing Starlette/HTTPX deprecation and pip disabled-cache warnings remained. The collection XML parsed, the scoped path assertion passed, and the Compose dry-render assertions above passed. Plan Bash blocks and embedded Python were syntax-checked without executing deployment or collection commands.

## Unverified behavior and approval boundary

End-to-end ingestion, root readability through Docker Desktop/WSL binds, private startup config application, logcollector activation, fresh request-ID matching in manager alerts, manager-local agent attribution, downstream indexer delivery/dashboard visibility, rotation/restart loss/duplication, and rollback execution remain unverified by this preparation. The allowed level-0 event is not expected in alerts.json; its absence cannot establish ingestion. Collection acceptance must use fresh denied-event IDs, not merely source-file growth or historical logtest results.

Correlation expiry remains unverified, not a confirmed rule defect. The earlier 61-second submission wait did not establish processing times; the next acknowledged run passed the inside case but stopped at an adapter cleanup-return mismatch. That harness has been corrected offline; the AI rules were rolled back. See [Investigation 002](../investigations/002-wazuh-correlation-expiry.md). No deployment retention or full-correlation claim is justified without the remaining approved validation.

Future configuration/mount changes, manager recreation, rule installation, active ingestion tests, and rollback require new explicit approval covering that scope. Current authorization was preparation only. No application behavior/dependencies, endpoints, SIEM repository, existing SSH detections, services, containers, or volumes were changed. No commit or push was performed.

## Subsequent approved implementation

The preparation plan was later executed under separate explicit approval. Manager-local collection, five fresh request-ID alerts, and their indexing were verified, with the integration retained. See [actual end-to-end evidence](milestone-06-end-to-end-wazuh-integration.md). This historical preparation record does not override the later observed results; expiry and production-hardening limitations remain.
