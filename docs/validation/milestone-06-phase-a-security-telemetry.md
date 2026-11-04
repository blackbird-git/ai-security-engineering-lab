# Milestone 6 Phase A: Structured telemetry and detection artifacts

- Date: November 4, 2026
- Scope: Historical Phase A record; later approved integration is linked below
- Decision: [ADR-0005](../security-decisions/ADR-0005-security-telemetry.md), now Accepted for the implemented scope

## Executed local demonstration

Executed from this repository without live inference or external connections:

```bash
.venv/bin/python -m app.telemetry_demo --log-file local/telemetry/security-events.jsonl
```

Exact output:

```text
authorized: allowed
customer_scope: denied
unknown_tool: denied
identity_override: denied
service_permission: denied
malformed: denied
events: {"CUSTOMER_SCOPE_DENIED": 1, "IDENTITY_OVERRIDE": 1, "MALFORMED_REQUEST": 1, "NONE": 1, "SERVICE_PERMISSION_DENIED": 1, "UNKNOWN_TOOL": 1}
storage: enabled
```

Exit status 0. Six generated JSONL lines were parsed with `json.loads` and validated with `serialize_event`: **six valid events, six distinct request IDs, one allowed and five denied outcomes**. They reflect actual Python decisions using fixed synthetic model proposals. No financial results, prompts, responses, supplied identities, or unknown tool names were logged. Runtime output is in ignored `local/telemetry/`; tracked samples are separately labeled illustrative fixtures.

Running `.venv/bin/python -m app.telemetry_demo` without `--log-file` exercises the same scenarios with `storage: disabled` and creates no files. Repeated explicit runs append; counts above describe one six-event run, not total lifetime file contents.

## Automated validation

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
git diff --check
git status --short
```

The complete suite passed all **312 tests** in 0.48 seconds outside the sandbox because of the previously observed health TestClient hang, including 48 new telemetry tests. The existing Starlette/HTTPX deprecation warning remained. `pip check` found no broken requirements and reported its existing disabled-cache permissions warning. `git diff --check` passed. The earlier targeted telemetry-plus-agent run passed 139 tests before the final six storage-failure cases were added. An initial regression test caught loss of exception suppression in a refactored denial path; it was corrected without changing the sanitized public error or allowing access.

New tests cover trusted reason generation, one-event denial behavior, service pseudonyms, no sensitive content, field validation, schema/size limits, ID propagation/uniqueness, default-disabled storage, permission/symlink/hardlink/path restrictions, capacity exhaustion, I/O/lock failures, pre-read fail-closed behavior, result rejection, CLI modes, sample schema, and structural Wazuh artifacts. Existing negative authorization tests remain intact.

## JSON and XML artifact checks

Validated the generated JSON as described above. Both `integrations/wazuh/ai_security_rules.xml` and `integrations/wazuh/localfile.example.xml` parsed successfully using Python's `xml.etree.ElementTree`: **well-formed XML**. Tests validate the sample JSON, unique rule IDs, JSON decoder/collector declarations, and repeated-pattern field/group references. This is not Wazuh XML semantic or rules-engine validation.

Proposed rules: 100600 schema recognition; 100601 generic denial; 100602 customer scope; 100603 unknown tool; 100604 identity override; 100605 service permission; 100606 malformed request; 100610 repeated failures for the same pseudonymous service (`frequency=5`, `timeframe=60`). See the [integration guide](../../integrations/wazuh/README.md) for approval-gated future steps and documentation references.

## Not validated and remaining requirements

- No live Ollama call was made. These events do not establish live model attack behavior, successful injection, compromise, or data disclosure.
- No Wazuh configuration, files, containers, or unrelated repositories were modified. No external network connection was made, including documentation fetches.
- `wazuh-logtest`, version-specific rule acceptance, decoder dynamic-field behavior, rule precedence/group correlation, exact repeated-failure threshold, positive/negative alert behavior, log collection, transport, and dashboard visibility remain **unvalidated**. Perform these only after separate deployment approval.
- Check custom rule-ID collisions, collector file visibility/permissions, reviewed host/container mounts, retention/rotation, and event integrity before integration. XML well-formedness alone cannot establish detection effectiveness.
- The file cap and fail-closed policy can deny legitimate reads under disk/lock/capacity failures. Denied-event loss, partial final lines, lack of crash durability, and absence of remote alerting are documented in ADR-0005.
- Fixture service identities are not real authentication; pseudonyms are not strong anonymization. Local process/host compromise can forge events. Existing unauthenticated Ollama, no total inference deadline, dummy-secret exact-match guard, and Starlette/HTTPX warning limitations remain.
- FastAPI stays health-only; its live binding was not revalidated during this phase. No Wazuh deployment or real SOC/production experience claim is made.

## Phase B preparation: confirmed read-only manager inspection

On November 4, 2026, inspected `single-node-wazuh.manager-1` using read-only Docker commands. The container is running `wazuh/wazuh-manager:4.14.9`; `wazuh-control info` reports `v4.14.9`, revision `rc2`, type `server`. The active ruleset loads both distribution `ruleset/rules` and custom `etc/rules` directories. `/var/ossec/etc` is a Docker volume; no writes to it were performed.

The custom rules directory contains only `local_rules.xml`, with SSH rule 100001 (level 5, parent 5716). Its SHA-256 is `991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4`. No IDs 100600–100610 were found in custom files or distribution XML rules. File ownership/mode are `wazuh:wazuh` / 0660. Existing SSH rules and configuration remain untouched.

The installed JSON decoder and distribution rules provide precedent for JSON dynamic fields and `if_matched_group` / `same_field` correlation. Logtest help confirms `-U rule:alert:decoder` and lacks an advertised alternate config/rule-directory option. Only utility help was invoked, not event testing; no new rule was loaded. Compatibility remains based on configuration/syntax inspection, not Wazuh parser or detection execution.

Review found that the proposed repeated-failure rule did not explicitly constrain the current event to a denial. The repository artifact only now adds a current parent/schema and denied-outcome guard, with structural test assertions. A subsequent allowed event after failure history is a mandatory engine negative test. The exact correlation threshold and group/child rule behavior remain unresolved.

The [Phase B procedure](../../integrations/wazuh/PHASE-B-PROCEDURE.md) includes confirmed inspection results, expected IDs/levels/event types, host-side recoverable backups, separate-file installation, fresh-session individual logtests, repeated/negative tests, SSH checksum and rule checks, and rollback limited to the new file. **None of its deployment/test/rollback commands were executed.** Backup configuration may contain secrets and must remain in the ignored private local directory.

Phase B local validation: all 312 tests passed in 0.50 seconds outside the sandbox, with the existing Starlette/HTTPX warning. `pip check` found no broken requirements (existing disabled-cache warning), `git diff --check` passed, both XML files were well formed, and all six sample JSON events passed schema validation. A final read-only checksum/listing confirmed the unchanged SSH file and absence of an installed AI rules file. No containers were restarted, rules installed, volumes modified, external documentation fetched, or unrelated repositories changed. Additional approval is required for any manager/volume modification, logtest engine execution, configuration reload/restart, collector setup, or rollback. The current task authorizes read-only preparation only; AGENTS.md independently requires explicit approval before Wazuh modifications.

## Subsequent approved installation attempt

The owner later authorized manager-only installation, engine tests, restart, SSH checks, and rollback. See the [Phase B execution record](milestone-06-phase-b-wazuh-rule-validation.md): individual and repeated detections were observed, but an unsynchronized 61-second expiry-test expectation failed. The AI installation was rolled back, original configuration/checksums preserved, and manager core services and SSH detection verified. AI rules were absent after that trial; it did not establish completed deployment or fully passing correlation validation.

## Current milestone outcome

Later approved collection and indexed-alert verification succeeded. See the [end-to-end validation](milestone-06-end-to-end-wazuh-integration.md) and [Investigation 003](../investigations/003-ai-agent-authorization-detection.md). The integration remains installed; correlation expiration remains unverified. Earlier statements above describe the historical phase, not current deployment state.
