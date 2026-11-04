# Phase B: Read-only inspection and proposed deployment procedure

This is the reviewed preparation plan. No deployment commands were executed during its original preparation. A later explicitly approved run temporarily installed/tested the AI rules, failed a correlation-expiry expectation, and completed rollback. See the [actual results and final restored state](../../docs/validation/milestone-06-phase-b-wazuh-rule-validation.md). The instructions below remain a plan, not evidence of a successful installation; another installation requires renewed authorization. No security-operations-lab files or unrelated components were modified.

## Confirmed read-only findings — November 4, 2026

| Check | Observed result |
| --- | --- |
| Container | `single-node-wazuh.manager-1`, running, image `wazuh/wazuh-manager:4.14.9` |
| `wazuh-control info` | Version `v4.14.9`, revision `rc2`, type `server` |
| Custom loading | Active `ossec.conf` ruleset contains `<rule_dir>etc/rules</rule_dir>` after distribution `ruleset/rules`; custom directory is therefore supported, not limited to `local_rules.xml`. |
| Existing custom files | Only `local_rules.xml`; owner/group `wazuh:wazuh`, mode 0660; directory is `root:wazuh`, mode 0770. |
| Existing SSH rule | 100001, level 5, parent 5716, source IP condition `1.1.1.1`; retain byte-for-byte. |
| ID conflicts | No rule IDs 100600–100610 in scanned custom files or distribution XML rules. Recheck immediately before deployment. |
| Configuration persistence | `/var/ossec/etc` is a read-write Docker volume. Installing there is a volume modification and is not authorized by this preparation task. |
| Testing utility | `/var/ossec/bin/wazuh-logtest` exists; help supports `-U rule:alert:decoder`, `-l`, `-q`, `-v`, `-d`, `-V`. No alternate rules-directory/config option is advertised. Only help was invoked. |
| Decoder | Installed JSON decoder uses `JSON_Decoder` with JSON-object prematch. |
| Installed syntax precedent | Distribution rules use JSON dynamic fields and `if_matched_group` plus dynamic `same_field` correlation. |

Existing `local_rules.xml` SHA-256:

```text
991dc926bd2e3aec88bd79be1c8b458777f64f489b3e6524e682ac33620425f4
```

Only the ruleset section of `ossec.conf` was printed, avoiding unrelated credentials/configuration. Installed precedent supports the proposed syntax but is not parser or rules-engine validation of these new rules. The existing SSH rule was read, not exercised or edited.

## Compatibility review and problems

- IDs are in the custom-rule range and currently conflict-free. Eight rules are defined; the reserved gap 100607–100609 is unused. Recheck includes the whole 100600–100610 range.
- JSON decoding, dotted dynamic field names, custom rule directories, and group/same-field correlation have matching installed conventions. No custom decoder or `ossec.conf` change is needed merely to load the separate XML file.
- The original 100610 rule constrained historical failures but lacked an explicit current-event denial condition. This left its behavior on a subsequent allowed event insufficiently constrained. The **repository artifact only** now requires current parent 100600 plus `outcome=denied`; the structural regression test checks this guard. The manager was not changed. A negative after failure history remains an essential engine test.
- `frequency=5` is configuration, not a verified fifth-event threshold. Version-specific counting, child/group inheritance, rule ordering, and correlation window behavior must be measured with logtest. Do not claim a repeated-failure detection works until those checks pass.
- The grouping rule is level 0 and is not itself expected to create an alert. Historical correlation uses nonzero denial rules/groups. Identity overrides are possible injection indicators, not confirmed successful attacks.
- This ruleset recognizes selected schema fields, not the entire application's schema/privacy contract. A hostile log writer can forge events; collector permissions and source integrity remain necessary.
- The collector sample's host path is not automatically visible inside a container. Collection/mount configuration is a separate approval and deployment step, not part of loading/test-driving rules.

## Proposed deployment — execute only after approval

Expected matches, not yet engine-confirmed:

| Event type / reason | Outcome / event severity | Expected rule / Wazuh level |
| --- | --- | --- |
| `tool_authorization` / `NONE` | allowed / info | 100600 / 0; no denial alert |
| `tool_authorization` / `CUSTOMER_SCOPE_DENIED` | denied / medium | 100602 / 7 |
| `tool_authorization` / `UNKNOWN_TOOL` | denied / medium | 100603 / 5 |
| `tool_authorization` / `IDENTITY_OVERRIDE` | denied / medium | 100604 / 7 |
| `tool_authorization` / `SERVICE_PERMISSION_DENIED` | denied / medium | 100605 / 5 |
| `tool_authorization` / `MALFORMED_REQUEST` | denied / medium | 100606 / 4 |
| `tool_authorization` / `UNKNOWN_SERVICE` | denied / medium | 100601 / 3 |
| `tool_result` / `RESULT_REJECTED` | denied / medium | 100601 / 3 |
| Repeated supported denied events, same service | denied / medium in source events | 100610 / 10 when configured correlation matches |

Source event severity and Wazuh alert level are different fields/scales. No rule establishes successful injection or data disclosure.

Use one Bash session from `/home/ilyam/ai-security-engineering-lab`. Stop on every failed assertion, test, changed checksum, or unexpected rule ID. Never replace `local_rules.xml`. The procedure deliberately stops short of restarting the manager or configuring collection.

### 1. Preflight and recoverable host backup

```bash
set -euo pipefail
umask 077
M6_MANAGER=single-node-wazuh.manager-1
mkdir -p local
M6_BACKUP_DIR="$(mktemp -d "$PWD/local/wazuh-phase-b-backup.XXXXXX")"
docker exec "$M6_MANAGER" test ! -e /var/ossec/etc/rules/ai_security_rules.xml
docker exec "$M6_MANAGER" test ! -e /var/ossec/etc/ai_security_rules.xml.pending
docker exec "$M6_MANAGER" sha256sum /var/ossec/etc/rules/local_rules.xml > "$M6_BACKUP_DIR/local_rules.sha256"
docker cp "$M6_MANAGER":/var/ossec/etc/rules "$M6_BACKUP_DIR/rules"
docker cp "$M6_MANAGER":/var/ossec/etc/ossec.conf "$M6_BACKUP_DIR/ossec.conf"
cp integrations/wazuh/ai_security_rules.xml "$M6_BACKUP_DIR/proposed_ai_security_rules.xml"
sha256sum "$M6_BACKUP_DIR/rules/local_rules.xml"
```

Compare the backup file's digest with `local_rules.sha256` (filenames differ, digests must match) and the inspected baseline above; stop and review if changed. Backup configuration may contain sensitive settings: keep the ignored, mode-0700 backup directory local and never print or commit its contents. Record its path privately for recovery. Backing up the full directory preserves all current custom rules, not just the SSH file.

Recheck IDs using this exact read-only command before installing:

```bash
docker exec -i "$M6_MANAGER" python3 - <<'PY'
from pathlib import Path
import re
roots = (Path('/var/ossec/etc/rules'), Path('/var/ossec/ruleset/rules'))
conflicts = [(str(p), value) for root in roots for p in root.rglob('*.xml')
             for value in re.findall(r'<rule\s+[^>]*id="(\d+)"', p.read_text())
             if 100600 <= int(value) <= 100610]
print('Conflicts:', conflicts)
raise SystemExit(bool(conflicts))
PY
```

### 2. Stage outside the rule directory, then install one separate file

```bash
docker cp integrations/wazuh/ai_security_rules.xml "$M6_MANAGER":/var/ossec/etc/ai_security_rules.xml.pending
docker exec "$M6_MANAGER" sh -c 'test ! -e /var/ossec/etc/rules/ai_security_rules.xml && chown wazuh:wazuh /var/ossec/etc/ai_security_rules.xml.pending && chmod 660 /var/ossec/etc/ai_security_rules.xml.pending && mv /var/ossec/etc/ai_security_rules.xml.pending /var/ossec/etc/rules/ai_security_rules.xml'
docker exec "$M6_MANAGER" sha256sum /var/ossec/etc/rules/local_rules.xml | diff - "$M6_BACKUP_DIR/local_rules.sha256"
docker exec "$M6_MANAGER" /var/ossec/bin/wazuh-analysisd -t
```

Any syntax error or failed SSH checksum comparison blocks further deployment. An analysisd test is not an active manager reload. Do not restart/reload automatically. Installing the file modifies the mounted volume; that is why this entire section requires approval.

### 3. Fresh logtest sessions for individual sample lines

Execute after installation approval. The following uses only tracked sanitized samples and starts a separate logtest invocation per case to avoid accumulated correlation history:

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path
import subprocess
expected = {'NONE': (100600, 0), 'CUSTOMER_SCOPE_DENIED': (100602, 7),
            'UNKNOWN_TOOL': (100603, 5), 'IDENTITY_OVERRIDE': (100604, 7),
            'SERVICE_PERMISSION_DENIED': (100605, 5), 'MALFORMED_REQUEST': (100606, 4)}
for line in Path('integrations/wazuh/samples/security-events.jsonl').read_text().splitlines():
    reason = json.loads(line)['ai_security']['denial_reason']
    rule, level = expected[reason]
    print('Expected:', reason, rule, level, flush=True)
    subprocess.run(['docker', 'exec', '-i', 'single-node-wazuh.manager-1',
                    '/var/ossec/bin/wazuh-logtest', '-U', f'{rule}:{level}:json'],
                   input=line + '\n', text=True, check=True)
PY
```

Expected level-0 grouping behavior must itself be checked: if the allowed-event `-U` assertion behaves differently, inspect full Phase 2/3 output rather than suppressing a failure. The acceptance criterion is correct schema decoding with **no AI denial or repeated-failure alert** for an allowed event. If new rules are not visible to fresh logtest sessions, stop and investigate the version's reload behavior; do not restart automatically or report success.

SSH preservation check (the existing rule's own illustrative log format):

```bash
printf '%s\n' 'Nov  4 12:00:00 labhost sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2' | docker exec -i "$M6_MANAGER" /var/ossec/bin/wazuh-logtest -U 100001:5:sshd
docker exec "$M6_MANAGER" sha256sum /var/ossec/etc/rules/local_rules.xml | diff - "$M6_BACKUP_DIR/local_rules.sha256"
```

The SSH logtest expectation is proposed, not yet observed. A failed expected decoder/rule requires investigation, not bypassing the check.

### 4. Repeated-failure and negative tests in one session

Create local, sanitized inputs (no changes inside the container):

```bash
.venv/bin/python - <<'PY'
import copy, json
from pathlib import Path
from uuid import uuid4
events = [json.loads(line) for line in Path('integrations/wazuh/samples/security-events.jsonl').read_text().splitlines()]
denied = next(e for e in events if e['ai_security']['denial_reason'] == 'CUSTOMER_SCOPE_DENIED')
allowed = next(e for e in events if e['ai_security']['denial_reason'] == 'NONE')
root = Path('local/wazuh-logtest-inputs')
root.mkdir(parents=True, exist_ok=True)
def fresh(event, second):
    result = copy.deepcopy(event)
    result['ai_security']['request_id'] = str(uuid4())
    result['ai_security']['timestamp'] = f'2026-11-04T12:00:{second:02d}.000Z'
    return result
def write(name, records):
    (root / name).write_text(''.join(json.dumps(record) + '\n' for record in records))
write('repeat.jsonl', [fresh(denied, i) for i in range(8)])
write('allowed-after-history.jsonl', [fresh(denied, i) for i in range(8)] + [fresh(allowed, 8)])
distinct = [fresh(denied, i) for i in range(4)]
for i, item in enumerate(distinct, 1):
    item['ai_security']['service_id'] = f'service-{i:02d}'
write('distinct-services.jsonl', distinct)
unknown = fresh(denied, 0)
unknown['ai_security']['schema_version'] = '2.0'
write('unknown-schema.jsonl', [unknown])
PY
docker exec -i "$M6_MANAGER" /var/ossec/bin/wazuh-logtest < local/wazuh-logtest-inputs/repeat.jsonl
docker exec -i "$M6_MANAGER" /var/ossec/bin/wazuh-logtest < local/wazuh-logtest-inputs/allowed-after-history.jsonl
docker exec -i "$M6_MANAGER" /var/ossec/bin/wazuh-logtest < local/wazuh-logtest-inputs/distinct-services.jsonl
docker exec -i "$M6_MANAGER" /var/ossec/bin/wazuh-logtest < local/wazuh-logtest-inputs/unknown-schema.jsonl
```

Inspect each event's Phase 3 output: repeat should eventually match 100610/level 10, an allowed final event must not match any AI denial rule, four distinct services must not aggregate, and unknown schema must not match AI rules. Record the actual event number triggering repetition. Logtest exit 0 alone is not evidence that these manual expectations passed. Do not repeat the old unsynchronized sleep-and-pipe expiry test. The [follow-up investigation](../../docs/investigations/002-wazuh-correlation-expiry.md) supersedes that timing approach with processed-event acknowledgments, timestamp records, stable-session checks, and a 70-second post-acknowledgment gap. After separately approved rule availability, use `.venv/bin/python -m integrations.wazuh.correlation_retest --run-approved-retest`. Without that flag it is plan-only and invokes no Docker command. Prior individual/group matches are recorded in Phase B evidence; complete synchronized expiry validation remains pending.

### 5. Stop for separate operational approval

Even if logtest passes, runtime manager reload/restart, collector changes, Docker mount changes, and transport/alert validation require separately approved work. Save sanitized engine evidence first. No current step enables log collection or proves a running manager alert.

## Rollback — planned, not executed

The planned installation creates exactly one new active file. First confirm that its checksum matches the installed proposal and that `local_rules.xml` still matches the backup. If ownership/content is unexpected, stop and investigate rather than deleting another operator's file.

After explicit rollback approval, remove only the known new file and any known leftover staging file:

```bash
docker exec "$M6_MANAGER" sha256sum /var/ossec/etc/rules/ai_security_rules.xml
sha256sum "$M6_BACKUP_DIR/proposed_ai_security_rules.xml"
# Proceed only if the two digests match.
docker exec "$M6_MANAGER" rm -- /var/ossec/etc/rules/ai_security_rules.xml
docker exec "$M6_MANAGER" sh -c 'if test -f /var/ossec/etc/ai_security_rules.xml.pending; then rm -- /var/ossec/etc/ai_security_rules.xml.pending; fi'
docker exec "$M6_MANAGER" sha256sum /var/ossec/etc/rules/local_rules.xml | diff - "$M6_BACKUP_DIR/local_rules.sha256"
docker exec "$M6_MANAGER" /var/ossec/bin/wazuh-analysisd -t
```

No existing rule file or configuration is removed/replaced. If an existing file was unexpectedly changed, the host backup is recoverable via `docker cp "$M6_BACKUP_DIR/rules/local_rules.xml" "$M6_MANAGER":/var/ossec/etc/rules/local_rules.xml`, followed by `chown wazuh:wazuh` and `chmod 660`; restoration is exceptional and requires separate owner approval after reviewing the difference. Do not blindly restore an entire directory over unrelated work. If a later approved runtime reload occurred, rollback also needs its own reviewed reload/restart plan; deleting the disk file alone does not guarantee unloading rules already held in memory.
