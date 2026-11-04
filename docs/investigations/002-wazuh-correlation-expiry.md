# Investigation 002: Wazuh correlation expiry timing

- Date: November 4, 2026
- Status: First acknowledged live case passed; retest aborted on cleanup-wrapper return mismatch and rolled back; cleanup corrected offline; expiry still unvalidated
- Rule: 100610, unchanged SHA-256 of complete candidate file `447f2f785e009a6896f4e213bb8d9f403fcbe6c042c43cb7f2020855211a6eaa`
- State: AI rules remain rolled back. Original investigation was read-only; a subsequent explicitly approved reinstall/retest and rollback are recorded below.

## Evidence reviewed

Reviewed the [Phase B record](../validation/milestone-06-phase-b-wazuh-rule-validation.md), deployment/testing commands, the saved `expired-window-logtest.txt` transcript, and the exact candidate XML. The transcript contains five matching decoded UUIDs and the sequence `100602, 100602, 100602, 100602, 100610`. It has no per-event host submission/result times or Wazuh output timestamps. Its nested `ai_security.timestamp` values all equal the synthetic fixture time; those are not processing-time measurements.

The original host script launched Docker/logtest, wrote four events, flushed stdin, slept for 30 + 31 seconds, and only then used `communicate(input=fifth)` to send the fifth event and read results. `flush()` confirms delivery to a pipe, not processing in Wazuh. It did **not** wait for acknowledgments before starting its timer. The measured interval was a host submission/wait interval, not the interval between actual Wazuh event processing.

## Version-specific implementation review

Read the manager's installed `/var/ossec/framework/scripts/wazuh_logtest.py` without executing it. Its loop reads one line with `input`, calls `process_log`, waits for the socket response, prints the result through Python logging, and then accepts another event. It starts with an empty session token, retains the returned token for subsequent events, warns on replacement, and removes its session at exit. Logging normally goes to stderr. This supports synchronous processing within one CLI client; it does not prove when the earlier Docker process started or each event reached it.

The tagged [Wazuh v4.14.9 logtest implementation](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.9/src/analysisd/logtest.c) creates/looks up per-token sessions, tracks inactivity separately, and processes an event before returning its response. New sessions load their own rules and state. Reusing one session within a correlation test is necessary; sharing it across unrelated test cases is undesirable. The [official testing documentation](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html) describes session-persistent counters and a default 15-minute inactivity timeout. Read-only inspection confirmed the manager explicitly configures `enabled=yes`, one thread, 64 maximum sessions, and a 15-minute inactivity timeout. The 61-second wait is below that timeout; token replacement must nevertheless invalidate the retest, even if the resulting rule looks correct.

In tagged [cleanevent.c](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.9/src/analysisd/cleanevent.c), preprocessing assigns internal generation time from the server clock. The [group-correlation implementation](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.9/src/analysisd/eventinfo.c) compares its current clock against historical generation times, excludes history when the difference is greater than `timeframe`, and compares dynamic fields for `same_field`. The [analysisd clock implementation](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.9/src/analysisd/analysisd.c) uses a cached clock refreshed in its log-rotation thread, normally at one-second intervals. Boundary timing and scheduler delays therefore merit margin. Altering an embedded JSON timestamp is not a valid substitute for elapsed server processing time.

The [rule syntax reference](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#same-field) describes `frequency` as the match count, `timeframe` as the correlation window, and `same_field` as dynamic-value equality. Rule 100610 specifies frequency 5, timeframe 60, historical group `ai_authorization_failure`, same `ai_security.service_id`, and a current schema-matching denied event. Prior live engine tests observed the fifth-event threshold, mixed-group matching, and service isolation. No evidence identifies a defect in this XML; it remains unchanged. Current documentation supplements the pinned 4.14.9 source, not vice versa.

## Assessment: likely cause versus unproven alternatives

Most likely, the **unsynchronized timing harness** caused an invalid expiry assertion: process startup/input delivery or processing delay could consume the very small margin between 61 host seconds and a 60-second engine window. This is an inference, not a reconstructed timeline or confirmed root cause. Missing acknowledgments are a demonstrated test defect; which delay occurred is unknown.

Input buffering and output backpressure remain possible but unproven. The installed client does not deliberately batch all stdin until EOF and performs synchronous request/reply. The saved transcript is about 5.3 KiB; a newly measured default pipe on the current host was 64 KiB, which weakens a simple full-host-pipe explanation but does not reconstruct Docker/internal/original pipe sizes. Asynchronous Docker startup and engine scheduling still prevent treating stdin flush as an acknowledgment.

Retained history within the single expiry session was intentional. Cross-test leakage is less likely because the old CLI starts with an empty token and ordinary exit cleans it up; transcript evidence alone cannot establish session identity/creation times. A session reset would normally lose history and prevent correlation rather than explain an unexpected hit. A cached/blocked clock or engine/build-specific behavior is an alternative to investigate only if synchronized timing still contradicts the expectation. No manager defect, frozen clock, or missing expiry mechanism has been demonstrated.

## Revised deterministic protocol

The reusable [correlation retest harness](../../integrations/wazuh/correlation_retest.py) is separate from application agent tools. It defaults to plan-only mode; no Docker invocation occurs without `--run-approved-retest`. It installs nothing, changes no configuration, restarts nothing, and cannot test rolled-back rules without a separately approved rule-availability setup.

For each case it creates a fresh bridge process/session using the installed synchronous `WazuhLogtest` client. The bridge sends only synthetic events, validates the decoded request UUID, refuses a changed server token, and returns only request ID, rule ID/level, and engine output timestamp. Server tokens, raw replies, financial data, and prompts are never exported. Session cleanup is explicit.

The host allows only **one in-flight event**. Each processed response must arrive within 20 seconds and match its request ID before the next event is sent. The host records UTC and monotonic submission/acknowledgment times plus the server output timestamp and actual rule ID. Partial results are preserved on mismatch; no failure is bypassed.

| Fresh-session case | Schedule and expected rules |
| --- | --- |
| Inside window | Five same-service failures, each acknowledged; `100602 × 4, 100610`, entire span under 50 seconds |
| Mixed group | Five different denial reasons, same service; `100602, 100603, 100604, 100605, 100610` |
| Different service | Four service-01 failures then one service-02 failure; `100602 × 5` |
| Allowed at threshold | Four acknowledged failures then allowed event; `100602 × 4, 100600` |
| Outside window | Four acknowledged failures; wait at least **70 monotonic seconds after acknowledgment four**; send fifth; `100602 × 5`. Require server output timestamps for events four/five to differ by at least 65 seconds. |
| Fresh history | Separate new session, one failure; only 100602 |

If the inside case is too slow, the outside server-time gap is insufficient, an ID is missing, a token changes, or cleanup fails, the result is failed/inconclusive—not a passing expiry result. Acknowledgment is stronger than submission timing but still not internal engine tracing; the exported server timestamp approximates preprocessing, not a direct observation of every cached correlation-clock update.

## Exact proposed commands — future authorization required

Safe plan-only command, executed during this investigation:

```bash
.venv/bin/python -m integrations.wazuh.correlation_retest
```

After separate authorization makes the exact candidate available to the named manager or an approved equivalent environment, run:

```bash
.venv/bin/python -m integrations.wazuh.correlation_retest --run-approved-retest
```

The execution mode preflights the installed XML SHA-256 against the repository candidate and otherwise refuses to run. It creates an exclusive mode-0600 sanitized timing JSONL under ignored `local/`. Do not execute installation instructions under the present investigation request; AI rules remain absent. The harness has been tested offline, **not against the live manager protocol**. Review its bridge against the installed version before the authorized retest.

## Validation and remaining work

The complete offline suite passed **327 tests** in 0.47 seconds, including 15 new harness tests. `pip check` found no broken requirements, and `git diff --check` passed. Existing Starlette/HTTPX and pip disabled-cache warnings remain. Only the plan-only CLI was executed; it confirmed no Docker execution. Offline tests cover one-flight acknowledgment timing, fresh-session history, fake clock/window expiry, different-service isolation, mismatched event IDs, invalid times/types, unexpected rules, timeouts, token replacement, cleanup, and sanitized bridge results. No candidate XML change was made. Read-only manager inspection and official source/documentation review were performed. No new engine event was submitted. Real synchronized expiry, session behavior under contention, server-time advancement under load, and live bridge interoperability remain pending. If the acknowledged 70-second case still correlates with valid server timestamps and unchanged session, preserve evidence and investigate the cached clock/group history before changing rule semantics.

## Subsequent owner-approved synchronized trial — stopped and rolled back

The owner explicitly approved fresh backups, reinstalling the reviewed XML, a manager-only restart, executing the harness, retention only on full success, and rollback on failure. The private backup is `local/<private-backup>/` (mode 0700, ignored). Source XML and samples were validated; AI files were absent and no ID conflicts were found before installation. An initial quoting error in the preflight scanner was corrected before any manager modification; the corrected check completed successfully.

The unchanged XML was installed separately with `wazuh:wazuh` / 0660, and only the manager was restarted. Configuration validation, baseline core health, existing-file checksums, and SSH rule 100001 / level 5 / decoder sshd all passed before the harness.

Executed exactly:

```bash
.venv/bin/python -m integrations.wazuh.correlation_retest --run-approved-retest
```

Private partial evidence: `local/correlation-retest-<run-id>.jsonl` (five acknowledged events, one stable session). All times below are UTC on November 4, 2026:

| Event | Submitted | Acknowledged | Server output timestamp | Rule |
| --- | --- | --- | --- | --- |
| 1 | 19:38:31.672364 | 19:38:32.001399 | 19:38:32.000 | 100602 / 7 |
| 2 | 19:38:32.001621 | 19:38:32.003216 | 19:38:32.002 | 100602 / 7 |
| 3 | 19:38:32.003376 | 19:38:32.004604 | 19:38:32.003 | 100602 / 7 |
| 4 | 19:38:32.004742 | 19:38:32.005816 | 19:38:32.005 | 100602 / 7 |
| 5 | 19:38:32.005949 | 19:38:32.007098 | 19:38:32.006 | 100610 / 10 |

Inside-window processing span was **0.006 server seconds**; first host submission to final acknowledgment was **0.334733994997805 monotonic seconds**. Every event's ID matched the processed reply and every timing predicate passed. These results establish the first inside-window case only.

### Confirmed harness cleanup defect

After that case, the process exited 1 before `mixed`, `different_service`, `allowed_at_threshold`, `outside`, or `fresh_history` ran. Read-only inspection confirmed that installed `WazuhLogtest.remove_last_session()` calls `remove_session(self.last_token)` but **does not return its Boolean result**. Its docstring advertises a Boolean/None contract that the implementation does not fully implement. The bridge incorrectly treated the wrapper's implicit `None` as cleanup failure and exited 2; the host reported an unsuccessful retest. This is a confirmed test-adapter defect, not evidence that the first correlation case failed or that the rule failed expiration.

The original fake client returned `True` from that wrapper, so the offline test did not reproduce installed behavior. The repository bridge now calls the Boolean-returning `remove_session(client.last_token)` directly, while preserving failure on a real `False`. Offline fixtures now reproduce the non-returning wrapper, token replacement remains rejected, and a new negative test verifies real cleanup failure still exits 2. **No live retry or reinstallation followed this correction.** It is not a passing cleanup interoperability result until retested live under a new authorization.

### Required rollback and final state

On the required-check failure, further integration stopped. The installed AI file matched the saved proposal, was removed alone, and the manager alone was restarted to unload it. Both active/staging AI files are absent, `wazuh-analysisd -t` passes, all ten baseline core daemons run, and SSH 100001 / 5 / sshd passed again after rollback. No indexer, dashboard, endpoint, Compose, or other-repository change occurred. No existing configuration needed restoration.

Before/after `local_rules.xml`: `991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4`.

Before/after `ossec.conf`: `b137a003c617aee4a980e9eb132ced34c746a7807089a67a107dbbae74518fce`.

After the offline correction, all **328 tests passed** in 0.52 seconds; `pip check` and `git diff --check` passed, with existing Starlette/HTTPX and disabled-cache warnings. The actual expiry behavior, outside-window timestamps, different-service isolation, mixed/fresh-session cases, and corrected live cleanup are **not validated by this new run**. Prior historical cases remain recorded separately. The original unsynchronized expiry mismatch remains unresolved; no rule change is justified by this cleanup defect. Nothing was committed or pushed.

## Subsequent collection outcome

The later separately approved [end-to-end integration](../validation/milestone-06-end-to-end-wazuh-integration.md) verified five indexed application denial alerts and retained the integration. This supersedes the historical installation state above, but does not validate correlation expiration or the corrected harness live cleanup. See [Investigation 003](003-ai-agent-authorization-detection.md).
