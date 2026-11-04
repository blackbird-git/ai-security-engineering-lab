# Milestone 6 Phase B: Approved Wazuh rule installation and engine validation

- Date: November 4, 2026
- Target: `single-node-wazuh.manager-1`, Wazuh `v4.14.9` (reported revision `rc2`)
- Status: Historical rule-only trials did not fully pass and were rolled back; later end-to-end integration succeeded (linked below)
- Scope: Manager-only custom rules, synthetic logtests, installation and rollback restarts, SSH preservation
- Decision: [ADR-0005](../security-decisions/ADR-0005-security-telemetry.md) is Accepted for the implemented scope
- Procedure: [reviewed Phase B plan](../../integrations/wazuh/PHASE-B-PROCEDURE.md)

## Authorization, backup, and installation

The owner explicitly approved private backups, separate-file installation, logtest execution, manager-only reload/restart, SSH validation, and rollback on failure. Approval did not include indexer, dashboard, endpoints, Docker Compose, other repositories, or collection configuration. None of those were changed.

Preflight confirmed the manager was running, core services were active, both AI target/staging paths were absent, and IDs 100600–100610 conflicted with neither custom nor distribution rules. The existing SSH baseline matched rule 100001, level 5, decoder `sshd`, with `Unit test OK` before installation.

Private recoverable host backup:

```text
local/<private-backup>/
```

The backup directory is mode 0700 and ignored by Git. It contains all prior custom rules, `ossec.conf`, the original SSH checksum, the proposed AI rules, and private synthetic logtest evidence. Configuration contents were never printed. The backed-up SSH file was independently hashed and matched the manager's baseline.

Source XML and all six JSON sample events were validated before installation. The AI XML was staged outside the rules directory, assigned `wazuh:wazuh` ownership and mode 0660, then moved into the previously absent target:

```text
/var/ossec/etc/rules/ai_security_rules.xml
```

`local_rules.xml` was not overwritten. `wazuh-analysisd -t` exited 0 before restart and again afterward, with no reported configuration errors. During installation, the AI file and repository source matched SHA-256:

```text
447f2f785e009a6896f4e213bb8d9f403fcbe6c042c43cb7f2020855211a6eaa
```

Fresh logtest sessions recognized the new file before restart. One successful installation `docker restart single-node-wazuh.manager-1` was then performed to activate the rules in the running manager. Container start time afterward was `2026-11-04T19:20:41.041566334Z`. No other container was restarted. A second manager-only restart was later performed for rollback, as recorded below.

## Individual rule results

Synthetic samples were submitted through fresh `wazuh-logtest` invocations with `-U rule:level:json`. All six original sample assertions passed both before and after restart. Generic denial cases were additionally tested using synthetic events.

| Scenario | Observed rule | Level | Result |
| --- | --- | --- | --- |
| Allowed authorization | 100600 | 0 | JSON decoded; grouping only, no AI denial alert |
| Unauthorized customer access | 100602 | 7 | Expected alert; unit assertion passed |
| Unknown tool invocation | 100603 | 5 | Expected alert; unit assertion passed |
| Identity override attempt | 100604 | 7 | Expected alert; unit assertion passed |
| Service permission violation | 100605 | 5 | Expected alert; unit assertion passed |
| Malformed tool request | 100606 | 4 | Expected alert; unit assertion passed |
| Unknown service, generic authorization denial | 100601 | 3 | Expected generic denial matched |
| `tool_result` / `RESULT_REJECTED` | 100601 | 3 | Expected generic result rejection matched |
| Repeated authorization failures | 100610 | 10 | Correlation matched on fifth same-service failure |

The decoder exposed the expected nested fields, including `ai_security.denial_reason`, `ai_security.request_id`, `ai_security.service_id`, and `ai_security.outcome`. These are engine tests over sanitized synthetic inputs, not evidence of a live model attack, collection transport, or indexer/dashboard alerts.

## Correlation and negative results

Each sequence used one logtest session; separate cases used fresh sessions to avoid shared history.

| Test | Actual matched sequence / observation | Result |
| --- | --- | --- |
| Eight same-service customer denials | `100602, 100602, 100602, 100602, 100610, 100602, 100602, 100602` | Fifth-event correlation confirmed for this run |
| Five mixed denial reasons, same service | `100602, 100603, 100604, 100605, 100610` | Group-based mixed-failure correlation confirmed |
| Eight denials followed by allowed event | Last event matched only 100600 / level 0 | No AI denial/repeated alert on allowed event |
| Four denials followed by allowed event at threshold | `100602, 100602, 100602, 100602, 100600` | Current-denial guard confirmed |
| Four different service aliases | Four 100602 matches, no 100610 | Different services did not aggregate |
| Four service-01 denials then service-02 denial | Five 100602 matches, no 100610 | Same-service grouping confirmed at threshold |
| Schema version 2.0 | Distribution rule 1002, no 100600–100610 | Did not match AI rules; not a claim of no distribution alert |
| Unrelated synthetic JSON | No matched rule ID reported | No AI rule match |
| Four failures submitted, real 61-second host wait, fifth failure submitted in same session | `100602, 100602, 100602, 100602, 100610` | Expiry expectation failed; triggered required stop and rollback. Engine processing times were not synchronized/observed. |

Individual rule levels, group inheritance, current-event gating, and a fifth-event match were observed in this manager version. The overall validation failed its expiry expectation and must not be reported as a passing deployment. The harness waited 61 real seconds after flushing the first four events to stdin, but did not synchronize against per-event engine output before waiting. Buffering/processing delay is therefore a plausible explanation, not an established root cause or proof that Wazuh ignores the configured window. No tuning, bypass, or reinstallation was attempted after the failure. This small deterministic test set is not a production false-positive evaluation.

## SSH preservation and manager health

The synthetic SSH scenario was tested before installation and after restart using:

```bash
printf '%s\n' 'Nov  4 12:00:00 labhost sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2' | docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest -U 100001:5:sshd
```

Pre-installation and post-installation/restart assertions passed; rollback SSH verification also passed: rule **100001**, level **5**, decoder **sshd**. The before/after `local_rules.xml` SHA-256 values were identical:

```text
Before: 991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4
After:  991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4
```

Post-restart core services matched the active baseline: analysisd, remoted, logcollector, syscheckd, modulesd, monitord, execd, db, authd, and apid running. Optional clusterd, maild, agentlessd, integratord, and csyslogd were inactive before and after. Following rollback, all ten baseline core daemons were verified running again. `wazuh-control status` returned 1 while reporting the optional inactive daemons; health was assessed from explicit core-daemon status rather than treating this as an all-daemons-running exit code.

## Local regression checks and remaining limitations

The complete offline application suite passed **312 tests** in 0.44 seconds; the existing Starlette/HTTPX deprecation warning remained. `pip check` found no broken requirements with the existing disabled-cache warning. `git diff --check` passed before documentation finalization. No application dependencies or behavior were changed during deployment.

## Failed expiry expectation and completed rollback

On the expiry-test mismatch, further deployment changes stopped. The installed AI file was checked against the saved proposal checksum and removed alone. The manager-only container was restarted again, with start time `2026-11-04T19:23:34.324001059Z`. Both `/var/ossec/etc/rules/ai_security_rules.xml` and its staging path are now absent. `wazuh-analysisd -t` exited 0 after removal/restart. `ossec.conf` matched the private backup byte-for-byte by SHA-256, and `local_rules.xml` retained the before/after digest above, so restoration of existing files was unnecessary.

The post-rollback SSH check was initially invoked without Docker's `-i`, delivering no event and returning a failed unit invocation. It was corrected to the reviewed command with `-i`; rule 100001 / level 5 / decoder sshd then returned `Unit test OK`. This was a harness correction, not a change to SSH rules. Both command outputs were preserved privately. No existing rules were deleted or overwritten.

**Final state: original manager rule/configuration state restored, AI rules not installed, core services running, SSH detection verified.** The private backup remains available. Before another attempt, investigate logtest input buffering/processing time with synchronized output acknowledgments or an approved isolated test environment, and repeat expiry and negative tests; obtain approval for a new installation. Do not infer a Wazuh engine defect from this unsynchronized harness result.

**Automatic application-log collection is not configured or tested**. No indexer ingestion, dashboard alert visibility, endpoint configuration, mount changes, active response, or external traffic was exercised. Source logs remain untrusted and unsigned; pseudonyms and fixture identities are not real authentication. Individual denials or possible injection indicators do not prove successful prompt injection or disclosure. ADR-0005 was Proposed at this historical trial; it is now Accepted for the later implemented scope.

## Follow-up investigation and revised retest

[Investigation 002](../investigations/002-wazuh-correlation-expiry.md) reviewed the installed client, tagged Wazuh 4.14.9 source, original commands, and saved transcript. The original 61-second wait was between host submissions, without observing processed-event acknowledgments; it did not establish the engine processing interval. Unsynchronized startup/delivery/processing is the leading test-related explanation, not a proven Wazuh defect. Client processing is synchronous per request and ordinarily starts a fresh session per invocation, weakening simple asynchronous-batch or inherited-session assumptions.

Rule 100610 remains unchanged. A new plan-only-by-default harness records paired submission/acknowledgment times, validates decoded event IDs and stable sessions, and requires a 70-second wait after the fourth acknowledgment plus at least 65 seconds of server timestamp advancement. It independently tests inside/outside windows, mixed failures, service isolation, allowed events, and new-session history. Only offline harness tests ran during investigation; no AI rule was reinstalled and no configuration/container change occurred. See the investigation for exact future commands and validation limitations.

## Second approved installation and synchronized trial

The owner subsequently authorized a new manager-only reinstall/retest with rollback on any required failure. Fresh private backup: `local/<private-backup>/` (0700, ignored). Preflight verified core health, absent AI active/staging files, no ID conflicts, and valid source XML/JSON. The reviewed XML was reinstalled at `/var/ossec/etc/rules/ai_security_rules.xml` with `wazuh:wazuh` / 0660, configuration validation passed, and the manager alone was restarted. SSH rule 100001 / level 5 / decoder sshd passed before the harness.

The exact approved harness command returned exit 1 after the first case. Its acknowledged sequence was **100602, 100602, 100602, 100602, 100610**; all timing predicates passed. Server processing timestamps spanned **0.006 seconds**, and host first-submission to last-acknowledgment spanned **0.334733994997805 monotonic seconds**. [Investigation 002](../investigations/002-wazuh-correlation-expiry.md#subsequent-owner-approved-synchronized-trial--stopped-and-rolled-back) records all five paired UTC timestamps. The sanitized partial record is `local/correlation-retest-<run-id>.jsonl`.

The abort was a confirmed cleanup-adapter error: the installed client's `remove_last_session()` discards the Boolean from `remove_session()`, but the bridge required a `True` return. The first case passed, then cleanup was incorrectly reported unsuccessful. **The outside-window wait never began.** Mixed failures, different-service isolation, allowed-at-threshold, and fresh-history cases were not reached in this run. Prior historical results do not substitute for completing this harness.

Per the owner's failure procedure, the AI file alone was removed after checking its proposal hash, and only the manager was restarted for rollback. All ten baseline core daemons were verified running, AI active/staging files absent, configuration validation successful, and SSH rule 100001 passed after rollback. No prior file needed restoration. Checksums were unchanged:

| File | Before | After |
| --- | --- | --- |
| `local_rules.xml` | `991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4` | `991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4` |
| `ossec.conf` | `b137a003c617aee4a980e9eb132ced34c746a7807089a67a107dbbae74518fce` | `b137a003c617aee4a980e9eb132ced34c746a7807089a67a107dbbae74518fce` |

The cleanup adapter was then corrected **offline only** to use the checked Boolean-returning primitive, and tests now model the installed wrapper's implicit `None` as well as genuine cleanup failure. All 328 tests passed in 0.52 seconds; dependency and whitespace checks passed with existing warnings. No live retry was performed and the rule XML was unchanged. Final state: **AI rules not installed; manager healthy; SSH preserved; synchronized expiry still pending**. No indexer/dashboard/endpoint/Compose or unrelated repository changes, commits, or pushes occurred.

## Subsequent collection preparation

The [collection preparation record](milestone-06-collection-preparation.md) and [exact implementation plan](../../integrations/wazuh/COLLECTION-PLAN.md) evaluate existing agent versus manager collection and recommend a manager-local collector with a dedicated read-only telemetry bind. Only read-only architecture checks and a Compose-model render were performed. No collection was deployed and AI rules remain absent. This does not change the unresolved expiry status or establish an end-to-end alert.

## Later approved end-to-end collection succeeded

A separate owner-approved implementation subsequently added the read-only telemetry bind/private startup config and reinstalled the same AI XML. All five fresh actual application denials were matched in real manager alerts and the existing Wazuh alert index; integration remains installed with SSH preserved. See the [end-to-end validation record](milestone-06-end-to-end-wazuh-integration.md). The failed historical harness trials above remain historical evidence, not the current installation state. Correlation expiry remains unverified; no inference to a confirmed rule defect is made.
