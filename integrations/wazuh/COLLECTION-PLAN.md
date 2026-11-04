# End-to-end collection plan and rollback

This is the reviewed implementation/rollback plan. A subsequent owner-approved execution succeeded and remains installed; see the [actual validation record](../../docs/validation/milestone-06-end-to-end-wazuh-integration.md). Do not rerun fresh-install preparation over active private files.

During original preparation, none of the configuration, mount, rule-installation, recreation, or test-generation commands below was executed. They were a future approval-gated procedure at that time; the later execution is recorded above. No Wazuh or Docker change was made during preparation, and no SIEM source file was modified during either preparation or implementation. At that preparation point AI rules were absent. Correlation expiry remains unverified; it is not a confirmed rule defect.

## Recommendation and inspected architecture

Use the **existing manager's local logcollector**, with a **dedicated read-only bind of the application's existing telemetry directory**. Do not introduce a forwarding daemon, application-side network sender, or new agent. This combines manager-local collection with narrowly scoped sharing; a shared directory by itself is not a collector.

Read-only inspection on November 4, 2026 confirmed:

- `single-node-wazuh.manager-1`, indexer, and dashboard use image version 4.14.9. The manager's Compose service is `wazuh.manager`, project directory `../security-operations-lab/wazuh-docker/single-node`, source file `docker-compose.yml`.
- The existing `security-endpoint-01` is registered and active as agent 002; the manager is local agent 000. The endpoint has only its read-only agent-key volume, no host telemetry mount. Its collector already monitors authentication/journald/package logs.
- The manager has no host AI telemetry mount. It has persistent `/var/ossec/etc` and `/var/ossec/logs` volumes, plus a startup config bind at `/wazuh-config-mount/etc/ossec.conf`. Its init script copies that startup config into `/var/ossec/etc` on container start. Editing only the live volume config is therefore not a reliable persistent setup.
- Both collectors run as user root/group wazuh. Docker reported seccomp/cgroupns security options, with no reported rootless/userns-remap option. Root access to a proposed bind still needs runtime verification, not assumption.
- Host `local/`, `local/telemetry/`, and the JSONL file are UID/GID 1000:1000; directories mode 0700, file mode 0600. Keep these restrictions. The application writer rejects group/world-accessible files.

| Option | Required changes | Assessment |
| --- | --- | --- |
| Existing endpoint agent | Add a host bind, change endpoint collection config, recreate/restart endpoint, plus manager rule work | Reuses agent transport but touches two components and the endpoint's unrelated monitoring. Not recommended for this host-local lab task. |
| Manager local collector without a mount | File is not visible; copying snapshots into a container would need a reliable relay and inode handling | Not a continuous integration path. Do not use ad hoc `docker cp` loops as forwarding. |
| Manager local collector plus dedicated read-only telemetry bind | One narrow bind, one localfile stanza, private startup-config override, manager-only recreation and separate AI rule file | Recommended: one affected container, no endpoint change, no application network dependency. |

Repository-relative host paths below resolve from the AI repository root. The shell assignment and deployed Compose override retain absolute paths for the verified installation; adapt them together for another clone.

## Exact paths and permissions

| Purpose | Path | Access |
| --- | --- | --- |
| Application source JSONL | `local/telemetry/security-events.jsonl` | Application UID 1000 owns it, mode 0600; parent telemetry directory 0700 |
| Container telemetry view | `/var/log/ai-security/security-events.jsonl` | Read-only bind of **only** host `local/telemetry/` |
| Private startup-config copy | `local/wazuh-collection/ossec.conf` | Host UID 1000, mode 0600, private parent 0700; never tracked/printed |
| Container startup config | `/wazuh-config-mount/etc/ossec.conf` | Private copy mounted read-only, replacing only the existing mount at that destination |
| Effective collector config | `/var/ossec/etc/ossec.conf` | Copied by the existing init script; retain baseline owner/mode and all existing settings |
| Separate AI rules | `/var/ossec/etc/rules/ai_security_rules.xml` | `wazuh:wazuh`, 0660; do not replace `local_rules.xml` |
| Manager alert output | `/var/ossec/logs/alerts/alerts.json` | Existing manager-local output, inspect narrowly by new request IDs |

The source bind excludes private backups, `.venv`, `.git`, application code, credentials, and the rest of `local/`. Neither app nor model gets access to manager sockets/configuration. No permissions need to be relaxed to 0644/0666. A later rotation/replacement must preserve owner UID and 0600 mode. Existing writer limits remain 1 MiB per file, with fail-closed behavior on capacity/I/O errors; no rotation is implemented by this plan.

## Required configuration

Use the candidate [Compose override](compose.collection.example.yml) stored in this repository, not edits to the SIEM Compose file. Its two volume entries add the read-only log directory and substitute the private startup-config copy at the existing config destination. All named volumes, certificates, networking, ports, environment, and other services must remain identical to the base model.

Merge only this element from [localfile.example.xml](localfile.example.xml) into the private config copy:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/ai-security/security-events.jsonl</location>
</localfile>
```

This follows Wazuh's [localfile JSON collection convention](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html). Do not replace the whole `ossec.conf` with the short XML example. Keep the custom rules as their existing separate XML artifact. Collection does not require a custom decoder; dotted JSON fields were already observed in logtest. Source-file schema validation does not authenticate a log writer.

## Future implementation procedure — do not execute without approval

### 1. Baseline, private backup, and config preparation

Reconfirm manager health, SSH 100001 baseline, absent/conflict-free AI IDs, and file permissions as in [Phase B](PHASE-B-PROCEDURE.md). Resolve the corrected harness's live cleanup/expiry validation under separate approval, or explicitly scope collection acceptance to individual alerts while recording correlation expiry as unverified. Never silently mark expiry complete.

From the AI repository, in one Bash session:

```bash
set -euo pipefail
umask 077
M6_BASE=/home/ilyam/security-operations-lab/wazuh-docker/single-node
M6_OVERRIDE="$PWD/integrations/wazuh/compose.collection.example.yml"
mkdir -p local
M6_COLLECTION_BACKUP="$(mktemp -d "$PWD/local/wazuh-collection-backup.XXXXXX")"
docker cp single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf "$M6_COLLECTION_BACKUP/ossec.conf"
docker cp single-node-wazuh.manager-1:/wazuh-config-mount/etc/ossec.conf "$M6_COLLECTION_BACKUP/startup-ossec.conf"
docker cp single-node-wazuh.manager-1:/var/ossec/etc/rules "$M6_COLLECTION_BACKUP/rules"
docker exec single-node-wazuh.manager-1 sha256sum /var/ossec/etc/rules/local_rules.xml > "$M6_COLLECTION_BACKUP/local_rules.sha256"
docker exec single-node-wazuh.manager-1 stat -c '%u:%g %a' /var/ossec/etc/ossec.conf > "$M6_COLLECTION_BACKUP/ossec-mode.txt"
test ! -e local/wazuh-collection
mkdir -m 700 local/wazuh-collection
cp "$M6_COLLECTION_BACKUP/ossec.conf" local/wazuh-collection/ossec.conf
chmod 600 local/wazuh-collection/ossec.conf
```

Do not print backup/config contents: they may contain existing credentials. Preserve the baseline SHA-256 and compare startup/effective config privately. The proposed copy starts from the current effective config so current settings are retained; if private comparison reveals startup-template/environment differences, review those before proceeding. Do not overwrite other local operators' staged config.

Insert the single block while preserving every original byte outside it:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
p = Path('local/wazuh-collection/ossec.conf')
old = p.read_text()
location = '/var/log/ai-security/security-events.jsonl'
assert location not in old and '</ossec_config>' in old
block = '\n  <!-- AI lab dedicated JSONL collection -->\n  <localfile>\n    <log_format>json</log_format>\n    <location>' + location + '</location>\n  </localfile>\n'
new = old.replace('</ossec_config>', block + '</ossec_config>', 1)
assert new.replace(block, '', 1) == old
# Wazuh may use multiple ossec_config roots, so wrap only for local syntax checking.
ET.fromstring('<validation_root>' + new + '</validation_root>')
p.write_text(new)
print('Single collection block inserted; original remainder preserved.')
PY
```

If the private file has an XML declaration or another format that prevents the wrapping check, stop and review rather than skipping validation. Do not serialize/reformat unrelated settings. The startup source mount is deliberately overridden: otherwise the next recreation could erase a volume-only collection edit.

### 2. Verify file creation, permissions, and merged Compose model

Create the sanitized log through the application writer if needed. This command creates actual six-event test traffic locally; it is not a read-only check and was not rerun for preparation:

```bash
.venv/bin/python -m app.telemetry_demo --log-file local/telemetry/security-events.jsonl
stat -c '%u:%g %a %n' local/telemetry local/telemetry/security-events.jsonl
docker compose --project-directory "$M6_BASE" -p single-node -f "$M6_BASE/docker-compose.yml" -f "$M6_OVERRIDE" config --quiet
```

Review the merged model privately before deployment: only the `wazuh.manager` volume list may differ. There must be exactly one log mount and one startup config mount, both read-only, with all other manager mounts and nonmanager services preserved. Privately compare explicitly configured manager environment/ports/image/network values with the running container as well; a difference between current runtime and Compose defaults blocks recreation until reviewed. Never print the fully interpolated Compose model or environment to chat/logs; it can contain credentials. `create_host_path: false` prevents silent directory creation for a missing source. Docker Desktop/WSL path translation must be verified after recreation.

### 3. Separate rules and manager-only recreation

After approved backups/ID checks, install `ai_security_rules.xml` using the reviewed separate-file procedure; leave `local_rules.xml` byte-for-byte unchanged. If a rule file is already installed by another approved task, verify its hash and baseline ownership instead of overwriting it. Save whether the AI file pre-existed so rollback removes only this change.

The new bind requires container **recreation**, not just `docker restart`. After explicit mount/configuration/recreation approval:

```bash
docker compose --project-directory "$M6_BASE" -p single-node -f "$M6_BASE/docker-compose.yml" -f "$M6_OVERRIDE" up -d --no-deps --no-build --pull never --force-recreate wazuh.manager
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logcollector -t
docker exec single-node-wazuh.manager-1 test -r /var/log/ai-security/security-events.jsonl
docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/log/ai-security"}}{{.Source}} rw={{.RW}}{{end}}{{end}}' single-node-wazuh.manager-1
docker exec single-node-wazuh.manager-1 sha256sum /var/ossec/etc/rules/local_rules.xml | diff - "$M6_COLLECTION_BACKUP/local_rules.sha256"
```

Require the expected source and `rw=false`. Check core daemons explicitly; optional inactive services can make `wazuh-control status` exit 1. Compare effective configuration privately to the baseline plus only the inserted block, accounting for documented init substitutions; stop/rollback on unexplained differences. Inspect collector startup messages for the exact new path without dumping unrelated log payloads. Repeat SSH rule 100001 / level 5 / decoder sshd using the Phase B synthetic example. Do not run `compose down`, recreate all services, or restart indexer/dashboard/endpoint. No additional restart should be necessary after recreation unless a diagnosed manager-only reload is separately approved.

### 4. Prove collection and alerting with new IDs

Only after the collector has opened the configured path, append a fresh application demo run. Do not rely on pre-existing lines being replayed; a collector may tail from its saved/current position. Record source-file length and time before/after, parse only newly appended lines, and save their request IDs under ignored `local/`. Use the writer's lock/capacity rules; do not truncate or replace an active file to force replay.

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path
import subprocess
p = Path('local/telemetry/security-events.jsonl')
before = p.stat().st_size
subprocess.run(['.venv/bin/python', '-m', 'app.telemetry_demo', '--log-file', str(p)], check=True)
with p.open('rb') as stream:
    stream.seek(before)
    new = [json.loads(line) for line in stream.read().splitlines()]
assert len(new) == 6
records = [{'request_id': e['ai_security']['request_id'], 'reason': e['ai_security']['denial_reason']} for e in new]
Path('local/wazuh-collection/source-request-ids.json').write_text(json.dumps(records))
print('Saved six fresh source IDs for ingestion matching; no financial content printed.')
PY
```

In a bounded polling window (for example 60 seconds), read the manager's existing `/var/ossec/logs/alerts/alerts.json` through `docker exec` and filter **in memory** against only these fresh IDs. Do not print or persist unrelated alerts or require new archives logging. Wazuh alert fields are expected at `data.ai_security.request_id` (or the decoder's dotted equivalent); inspect only matched sanitized records and export request ID, rule ID/level, and location. Require the collected alert location `/var/log/ai-security/security-events.jsonl`, manager-local agent ID 000, and expected individual IDs: customer scope 100602/7, unknown tool 100603/5, identity override 100604/7, service permission 100605/5, malformed 100606/4. Because these five denials arrive together, one may instead match correlation 100610/10; save that actual result rather than counting it as a missing individual event. Test individual expected IDs separately in fresh logtest sessions; do not disable correlation to make ingestion assertions pass.

The allowed event is level 0 and is not expected in alerts.json. Its absence alone does not prove it was ingested. A matched fresh denial ID proves that record traversed file collection and rule analysis. Source-file growth and collector-open messages alone are weaker evidence, not a complete ingestion check. If no matching alert arrives, diagnose visibility, permissions, collector syntax/open state, timestamps/rotation, and installed rule IDs; do not loosen file permissions or claim success based solely on logtest. Existing indexer/dashboard visibility can be checked later, read-only and explicitly authorized, without changing them; it is a separate downstream acceptance step from manager-local alerting.

Exact manager-alert polling example, after the fresh source-ID command above (future approved execution only):

```bash
.venv/bin/python - <<'PY'
import json, subprocess, time
from pathlib import Path
source = json.loads(Path('local/wazuh-collection/source-request-ids.json').read_text())
expected = {'CUSTOMER_SCOPE_DENIED': (100602, 7), 'UNKNOWN_TOOL': (100603, 5),
            'IDENTITY_OVERRIDE': (100604, 7), 'SERVICE_PERMISSION_DENIED': (100605, 5),
            'MALFORMED_REQUEST': (100606, 4)}
wanted = {item['request_id']: expected[item['reason']] for item in source if item['reason'] != 'NONE'}
seen = {}
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    result = subprocess.run(['docker', 'exec', 'single-node-wazuh.manager-1',
                             'tail', '-n', '2000', '/var/ossec/logs/alerts/alerts.json'],
                            capture_output=True, text=True, timeout=10, check=True)
    for line in result.stdout.splitlines():
        try:
            alert = json.loads(line)
        except ValueError:
            continue
        data = alert.get('data', {})
        fields = data.get('ai_security', {})
        request_id = fields.get('request_id', data.get('ai_security.request_id'))
        if request_id not in wanted:
            continue
        rule = (int(alert['rule']['id']), int(alert['rule']['level']))
        assert rule in (wanted[request_id], (100610, 10)), 'Unexpected rule for fresh source ID'
        assert alert.get('location') == '/var/log/ai-security/security-events.jsonl'
        assert alert.get('agent', {}).get('id') == '000'
        seen[request_id] = {'request_id': request_id, 'rule_id': rule[0], 'level': rule[1],
                            'location': alert['location'], 'agent_id': '000'}
    if len(seen) == len(wanted) == 5:
        break
    time.sleep(1)
assert len(seen) == len(wanted) == 5, 'Fresh denied events not all observed in manager alerts'
Path('local/wazuh-collection/matched-alert-evidence.json').write_text(json.dumps(list(seen.values())))
print('Five fresh denial IDs matched manager alerts; saved sanitized evidence only.')
PY
```

This bounded last-2,000-line view is for a quiet lab. Heavy alert traffic or rotation may require a separately reviewed larger/streaming window; do not treat a missed poll window as proof of application or rule failure. The command never prints or saves unrelated alerts. It validates manager-local analysis, not downstream delivery to indexer/dashboard.

## Rollback — future approved changes only

1. Stop generating AI demo traffic; do not delete or truncate its source log. Preserve private evidence and backups.
2. If this procedure newly installed AI rules, verify the candidate checksum and remove only `/var/ossec/etc/rules/ai_security_rules.xml` using the Phase B rollback. Preserve any pre-existing rule installation and all SSH rules.
3. Recreate **only** the manager with the original base Compose model, omitting this repository's override:

   ```bash
   docker compose --project-directory "$M6_BASE" -p single-node -f "$M6_BASE/docker-compose.yml" up -d --no-deps --no-build --pull never --force-recreate wazuh.manager
   ```

   This removes the new log bind and restores the original startup-config bind. It does not remove named volumes. Verify original configuration/checksums, expected base mounts, health, and SSH afterward. Do not run `down -v` or edit the SIEM source file.
4. If the effective config differs from the exact pre-change backup after normal startup, privately review the difference. Restore only the backed-up `/var/ossec/etc/ossec.conf`, its recorded owner/mode, and an approved manager-only reload if required. Do not overwrite unrelated rule/config files or revert another operator's intervening work. The original startup-source file was never edited, so no source repository restoration is needed.
5. Keep the candidate/private files as disabled evidence until retention is decided. Future operational commands must consistently include the override while it is deployed; using the base model alone recreates the baseline and removes collection. Document this operator dependency.

If step 4 is necessary and separately approved after reviewing the private difference:

```bash
docker cp "$M6_COLLECTION_BACKUP/ossec.conf" single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf
read -r M6_ORIGINAL_OWNER M6_ORIGINAL_MODE < "$M6_COLLECTION_BACKUP/ossec-mode.txt"
docker exec single-node-wazuh.manager-1 chown "$M6_ORIGINAL_OWNER" /var/ossec/etc/ossec.conf
docker exec single-node-wazuh.manager-1 chmod "$M6_ORIGINAL_MODE" /var/ossec/etc/ossec.conf
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logcollector -t
```

Validation alone does not reload an already running process; perform only an approved manager-only restart/reload if the restored live file must be reapplied. Check health, the original SSH checksum and synthetic SSH rule 100001 afterward. Do not restart other services to resolve collection problems.

## Risks and outstanding validation

This plan adds manager read access only to sanitized telemetry, but a compromised app can forge events and a privileged/compromised collector can read its mount. Read-only binds protect the writer from collector writes, not from disclosure or root-level host attacks. Docker Desktop/WSL sharing and root/user mapping are not proven by a rendered Compose model. Manager recreation interrupts analysis briefly. Configuration copies can drift and may contain existing secrets; keep them private and review them before each deployment.

The 1 MiB cap can deny legitimate app reads because enabled logging fails closed; retention/rotation is still unimplemented. Host filesystem delivery is not a durable acknowledgment to Wazuh, and duplicate/replayed/lost events remain possible around restarts/rotation. Correlation expiration has not passed a synchronized live test: the prior wait was unsynchronized and a later acknowledged test stopped at a cleanup-adapter defect, now corrected offline. This is not an established rule defect. No collection, mount readability, new config startup, live ingestion, manager alert, indexer, or dashboard acceptance result is claimed by this preparation.
