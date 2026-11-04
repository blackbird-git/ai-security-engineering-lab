# Wazuh AI security collection and detection

Current state: manager-local JSONL collection and separate AI rules are installed after an explicitly approved end-to-end run. Five fresh application denial IDs matched real manager alerts and the existing Wazuh alert index. See the [actual integration evidence](../../docs/validation/milestone-06-end-to-end-wazuh-integration.md). Correlation expiration remains unverified; ADR-0005 is Accepted for the implemented scope.

Historical preparation targeted the owner's separate Wazuh 4.14.9 lab. The initial candidates were not deployed during preparation; the later approved implementation is recorded above. Phase A made no Wazuh changes or SIEM delivery; a later approved manager-only trial was rolled back. During that preparation, no collector, indexer, dashboard, endpoint, Compose, or unrelated repository configuration was changed. Changes to Wazuh require separate explicit approval.

Phase B read-only preparation confirmed the manager version, custom rule-directory loading, preservation baseline for SSH rule 100001, and no ID conflicts in 100600–100610. See the [exact deployment, logtest, and rollback procedure](PHASE-B-PROCEDURE.md). During a subsequent explicitly approved run, AI rules were temporarily installed and exercised. Individual, repeated, and negative cases passed, but a correlation-expiry expectation failed; the AI file was removed and the manager restored. See the [actual installation/rollback evidence](../../docs/validation/milestone-06-phase-b-wazuh-rule-validation.md). The earlier rule-only trials left no AI rules installed; the later collection implementation explicitly reinstalled and retained them. The repository's 100610 rule now explicitly requires a current denied AI event as well as historical failures; the current-denial negative passed in logtest, but expiry remains unverified despite the later verified collection deployment.

## Artifacts and schema

- `ai_security_rules.xml`: custom manager rules, IDs 100600–100606 and 100610. Check for ID collisions before installation.
- `localfile.example.xml`: JSON log collection example. Merge its `localfile` element into an approved collector configuration; do not overwrite an existing configuration.
- `samples/security-events.jsonl`: six explicitly illustrative sanitized events, including an allowed decision and the five main denial reasons. Fixed timestamps are example values, not captured live timestamps.
- [ADR-0005](../../docs/security-decisions/ADR-0005-security-telemetry.md): event schema, privacy, and failure policy.

Every line is a standalone JSON object under `ai_security`. Wazuh's JSON decoder is expected to expose nested values as dynamic fields such as `ai_security.denial_reason`. No custom decoder is proposed. The collector uses `log_format=json`; these are JSONL records, not a JSON array or multiline pretty-printed JSON.

## Implemented detections

| Rule | Purpose | Level |
| --- | --- | --- |
| 100600 | Recognize schema 1.0 and supported event types via the JSON decoder | 0 |
| 100601 | Generic denied authorization or result rejection | 3 |
| 100602 | Customer scope denied | 7 |
| 100603 | Unknown tool denied | 5 |
| 100604 | Identity override fields rejected; possible injection indicator | 7 |
| 100605 | Service tool permission denied | 5 |
| 100606 | Malformed tool proposal rejected | 4 |
| 100610 | Repeated failures in group `ai_authorization_failure`, same pseudonymous service; `frequency=5`, `timeframe=60` | 10 |

Denial events document actual Python decisions; they do not prove successful prompt injection, model compromise, or data disclosure. Identity override fields are an observable indicator only. Repetition can arise from bugs or test traffic. Unknown services share a pseudonym and may aggregate unrelated failures. Levels and thresholds are proposed lab tuning choices, not calibrated production detections.

## Future integration steps — approval required

For the inspected Docker/WSL architecture, use the [end-to-end collection plan](COLLECTION-PLAN.md): the existing manager logcollector plus a dedicated read-only bind of host `local/telemetry/` at `/var/log/ai-security/`. The candidate [AI-repository Compose override](compose.collection.example.yml) changes only the manager's mounts and uses a private startup-config copy, avoiding edits to security-operations-lab. That override is now deployed with the approved private copy; do not rerun its preparation commands over the active private file. `localfile.example.xml` now uses the container-visible path rather than the inaccessible host-repository path.

1. Review target collector/manager, permissions, rule-ID availability, retention, and configuration backups with the owner. Check the documentation against Wazuh 4.14.9 before deployment. No runtime installation steps were executed in Phase A.
2. Generate the local file explicitly, from this repository:

   ```bash
   .venv/bin/python -m app.telemetry_demo --log-file local/telemetry/security-events.jsonl
   ```

3. After separate approval, provide a collector with read-only visibility of that exact file and least-privilege read access. A path on the Ubuntu host is not automatically visible inside a Wazuh container; review a read-only mount or an agent-local collection location. Do not mount credentials or the entire repository. The writer creates mode-0600 files; preserve restrictive access rather than making logs world-readable.
4. Merge the `localfile` example into the chosen collector's `ossec.conf`. Its path must refer to the path visible to that collector. Do not run this configuration as an application-side network sender.
5. After approval, place the reviewed custom rules in the manager's custom rules directory, conventionally `/var/ossec/etc/rules/`, with an appropriate unique filename. Test representative JSON lines with `/var/ossec/bin/wazuh-logtest` in the intended manager context before applying/restarting anything. Keep distribution rules untouched. A container deployment requires its own reviewed persistent configuration path; no Docker commands are supplied or executed here.
6. Verify JSON decoding and expected individual rule IDs. Exercise repeated failures in one logtest session/controlled collection interval, different service pseudonyms, allowed-event negatives, unknown schema versions, and events outside the correlation window. Verify actual frequency semantics, group inheritance, and whether 100610 fires at the intended threshold in this version. XML parsing alone does not establish these behaviors.
7. After approval and successful engine testing, apply collector/manager changes using the deployment's established process. Verify event delivery and alerts in Wazuh, inspect field retention and source permissions, and document sanitized evidence. Do not configure active response or model-driven SIEM changes.

The local writer stops at 1 MiB and does not rotate. Enabled operations fail closed before a data read if an authorization event cannot be appended. Review supervised retention/rotation and collector behavior before ongoing use; Phase A must not be treated as an unattended production audit pipeline.

## Documentation references and validation boundary

The examples use Wazuh's documented [JSON decoder convention](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), [custom rule conventions](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html), [rule XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html), and [ruleset testing workflow](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html). These are reference links, not evidence of an executed integration. No external connections or online documentation fetches were made under the task's network restriction. The subsequent approved 4.14.9 trial accepted the rule syntax and matched individual detections, but failed an expiry expectation and was rolled back; see the execution evidence above.

Phase A performed only local schema/XML/structural checks. The later approved Phase B engine/deployment trial and rollback are recorded separately; collection and indexed-alert delivery were subsequently verified in the end-to-end record; dashboard UI inspection remains unperformed. See the [Phase A validation record](../../docs/validation/milestone-06-phase-a-security-telemetry.md).

## Expiry-test investigation

[Investigation 002](../../docs/investigations/002-wazuh-correlation-expiry.md) documents why the original host wait did not establish processing-time separation. Rule 100610 is unchanged. A reusable acknowledged retest harness defaults to a no-Docker plan: `.venv/bin/python -m integrations.wazuh.correlation_retest`. Actual retesting requires separate approval and an approved loaded candidate; no reinstallation, manager testing, or restart occurred during the investigation.

## Current operations

Manager recreation must use the original base Compose model **and** `integrations/wazuh/compose.collection.example.yml` with the original `single-node` project and project directory. Base-only recreation removes the telemetry/config binds. Never commit `local/wazuh-collection/ossec.conf` or private backups. The [collection plan](COLLECTION-PLAN.md) contains the full integration rollback; a rule-only rollback does not remove collection mounts. SSH 100001, original named volumes, other services, and SIEM source files were verified preserved. No indexer/dashboard reconfiguration was performed.

For reproducible offline commands and a portable, approval-gated deployment entry point, see [REPRODUCE.md](REPRODUCE.md). No private backup or owner credentials are required from this repository.
