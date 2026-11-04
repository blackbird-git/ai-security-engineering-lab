"""Acknowledged, single-flight logtest retest. Default mode never invokes Docker."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
from uuid import uuid4

from app.security_telemetry import make_event


MANAGER = "single-node-wazuh.manager-1"
ROOT = Path(__file__).resolve().parents[2]
OUTSIDE_WAIT = 70

# Executed only after explicit opt-in, without copying a script into the manager.
# Use the installed client's synchronous protocol and explicit session cleanup.
BRIDGE = r'''
import json, sys
sys.path.insert(0, '/var/ossec/framework/scripts')
from wazuh_logtest import WazuhLogtest
client = WazuhLogtest(location='ai-lab-correlation-retest')
token = ''
try:
    for line in sys.stdin:
        try:
            item = json.loads(line)
            reply = client.process_log(json.dumps(item['event']), token)
            if token and reply['token'] != token:
                raise ValueError('Session changed')
            token = reply['token']
            output = reply['output']
            data = output.get('data', {})
            event_id = data.get('ai_security.request_id')
            if event_id is None:
                event_id = data.get('ai_security', {}).get('request_id')
            if event_id != item['event']['ai_security']['request_id']:
                raise ValueError('No matching decoded event ID')
            rule = output.get('rule', {})
            print(json.dumps({'request_id': event_id, 'rule_id': int(rule['id']),
                              'level': int(rule['level']),
                              'engine_utc': output['timestamp']}), flush=True)
        except Exception:
            print('{"error":"logtest_request_failed"}', flush=True)
            break
finally:
    # In 4.14.9 remove_last_session() discards remove_session()'s bool.
    # Call the checked primitive directly; never mistake its wrapper's None for failure.
    ok = client.remove_session(client.last_token) if client.last_token else True
    if ok is not True:
        sys.exit(2)
'''


class RetestError(Exception):
    """Sanitized retest failure; never contains session tokens or raw events."""


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def engine_seconds(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.timestamp()
    except (ValueError, TypeError, AttributeError):
        raise RetestError("Missing or invalid engine time.") from None


class DockerSession:
    """One fresh server session per bridge process; no shell or API credentials."""

    def __enter__(self):
        self.process = subprocess.Popen(
            ["docker", "exec", "-i", MANAGER, "/var/ossec/framework/python/bin/python3",
             "-u", "-c", BRIDGE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self.pending = b""
        return self

    def exchange(self, event):
        try:
            self.process.stdin.write((json.dumps({"event": event}) + "\n").encode())
            self.process.stdin.flush()
            deadline = time.monotonic() + 20
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdout, selectors.EVENT_READ)
                while b"\n" not in self.pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise RetestError("Timed out waiting for a processed event.")
                    chunk = os.read(self.process.stdout.fileno(), 4096)
                    if not chunk:
                        raise RetestError("Logtest bridge exited before acknowledgment.")
                    self.pending += chunk
                    if len(self.pending) > 8192:
                        raise RetestError("Oversized logtest acknowledgment.")
            line, self.pending = self.pending.split(b"\n", 1)
            reply = json.loads(line)
            if type(reply) is not dict or set(reply) != {"request_id", "rule_id", "level", "engine_utc"}:
                raise RetestError("Invalid logtest acknowledgment or changed session.")
            return reply
        except (OSError, ValueError):
            raise RetestError("Logtest exchange failed.") from None

    def __exit__(self, exc_type, exc, traceback):
        try:
            self.process.stdin.close()
            status = self.process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()
            self.process.wait(timeout=5)
            status = -1
        finally:
            self.process.stdout.close()
        if status != 0 and exc_type is None:
            raise RetestError("Logtest session cleanup failed.")


def synthetic_event(reason="CUSTOMER_SCOPE_DENIED", service="service-01"):
    tool = {"UNKNOWN_TOOL": "unknown", "MALFORMED_REQUEST": "none",
            "SERVICE_PERMISSION_DENIED": "get_customer_transactions"}.get(reason, "get_customer_account")
    value = make_event(request_id=str(uuid4()), service_subject="svc-amber-account",
                       tool_id=tool, reason=reason)
    value["ai_security"]["service_id"] = service
    return value


def run_cases(session_factory, record, *, clock=time.monotonic, sleep=time.sleep):
    """Injectable I/O/clock for offline tests; no rule installation or restart."""
    cases = (
        ("inside", ["CUSTOMER_SCOPE_DENIED"] * 5, [100602] * 4 + [100610]),
        ("mixed", ["CUSTOMER_SCOPE_DENIED", "UNKNOWN_TOOL", "IDENTITY_OVERRIDE", "SERVICE_PERMISSION_DENIED", "MALFORMED_REQUEST"],
         [100602, 100603, 100604, 100605, 100610]),
        ("different_service", ["CUSTOMER_SCOPE_DENIED"] * 5, [100602] * 5),
        ("allowed_at_threshold", ["CUSTOMER_SCOPE_DENIED"] * 4 + ["NONE"], [100602] * 4 + [100600]),
        ("outside", ["CUSTOMER_SCOPE_DENIED"] * 5, [100602] * 5),
        ("fresh_history", ["CUSTOMER_SCOPE_DENIED"], [100602]),
    )
    levels = {100600: 0, 100602: 7, 100603: 5, 100604: 7, 100605: 5, 100606: 4, 100610: 10}
    for name, reasons, expected in cases:
        session_id = str(uuid4())  # Local identifier, not the server's session token.
        engine_times, first_submit, last_ack = [], clock(), None
        with session_factory() as session:
            for index, (reason, expected_rule) in enumerate(zip(reasons, expected), 1):
                if name == "outside" and index == 5:
                    deadline = last_ack + OUTSIDE_WAIT
                    while clock() < deadline:
                        sleep(min(1, deadline - clock()))
                event = synthetic_event(reason, "service-02" if name == "different_service" and index == 5 else "service-01")
                submitted_mono, submitted_utc = clock(), utc_now()
                reply = session.exchange(event)  # No next submission until processed reply.
                acknowledged_mono, acknowledged_utc = clock(), utc_now()
                if reply.get("request_id") != event["ai_security"]["request_id"]:
                    raise RetestError("Decoded event ID did not match the submission.")
                if type(reply.get("rule_id")) is not int or type(reply.get("level")) is not int:
                    raise RetestError("Invalid rule result types.")
                processed = engine_seconds(reply.get("engine_utc"))
                engine_times.append(processed)
                timing_valid = True
                if name == "outside" and index == 5:
                    timing_valid = submitted_mono - last_ack >= OUTSIDE_WAIT and processed - engine_times[-2] >= 65
                elif name in {"inside", "mixed"}:
                    timing_valid = acknowledged_mono - first_submit < 50 and 0 <= processed - engine_times[0] < 50
                result = {"case": name, "sequence": index, "session_id": session_id,
                          "request_id": reply["request_id"], "submitted_utc": submitted_utc,
                          "acknowledged_utc": acknowledged_utc, "submitted_monotonic": submitted_mono,
                          "acknowledged_monotonic": acknowledged_mono, "engine_utc": reply["engine_utc"],
                          "rule_id": reply["rule_id"], "level": reply["level"],
                          "expected_rule_id": expected_rule, "timing_valid": timing_valid}
                record(result)  # Preserve the actual result even when assertion fails.
                if not timing_valid:
                    raise RetestError("Timing not established; result is inconclusive.")
                if reply["rule_id"] != expected_rule or reply["level"] != levels[expected_rule]:
                    raise RetestError("Unexpected rule result; stop the retest.")
                last_ack = acknowledged_mono


def main(argv=None):
    parser = argparse.ArgumentParser(description="Synchronized synthetic correlation retest; no deployment")
    parser.add_argument("--run-approved-retest", action="store_true")
    args = parser.parse_args(argv)
    if not args.run_approved_retest:
        print("PLAN ONLY: inside, mixed, different_service, allowed_at_threshold, outside (70s), fresh_history.")
        print("No Docker execution. Approved rule availability and retest authorization are prerequisites.")
        return 0
    try:
        source = (ROOT / "integrations/wazuh/ai_security_rules.xml").read_bytes()
        checked = subprocess.run(["docker", "exec", MANAGER, "sha256sum", "/var/ossec/etc/rules/ai_security_rules.xml"],
                                 capture_output=True, text=True, timeout=10, check=True)
        if checked.stdout.split()[0] != hashlib.sha256(source).hexdigest():
            raise RetestError("Loaded candidate file differs from source.")
        local = ROOT / "local"
        if local.is_symlink():
            raise RetestError("Unsafe local output directory.")
        local.mkdir(mode=0o700, exist_ok=True)
        output = local / ("correlation-retest-" + str(uuid4()) + ".jsonl")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            def record(result):
                stream.write(json.dumps(result) + "\n")
                stream.flush()
                print(f"{result['case']} #{result['sequence']}: rule={result['rule_id']} timing_valid={result['timing_valid']}", flush=True)
            run_cases(DockerSession, record)
        print("Retest passed. Sanitized timing evidence: " + str(output))
    except (RetestError, OSError, ValueError, IndexError, subprocess.SubprocessError):
        print("Retest failed or prerequisites unavailable; inspect private partial evidence. No deployment/restart performed.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
