"""Offline tests; no Docker, Wazuh socket, deployment, or real-time waits."""

from datetime import datetime, timezone
import json
import io
import socket
import sys
from types import SimpleNamespace

import pytest

from integrations.wazuh import correlation_retest as retest


@pytest.fixture(autouse=True)
def no_external_io(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Unexpected Docker/network operation")
    monkeypatch.setattr(retest.subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


class Clock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []
    def now(self):
        return self.value
    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def factory(clock, sessions, alter=None):
    class Session:
        def __enter__(self):
            self.history = {}
            self.calls = 0
            sessions.append(self)
            return self
        def __exit__(self, *args):
            self.closed = True
        def exchange(self, event):
            self.calls += 1
            clock.value += 0.01  # Acknowledgment received only after fake processing.
            fields = event["ai_security"]
            service = fields["service_id"]
            recent = [value for value in self.history.get(service, []) if clock.value - value <= 60]
            reason = fields["denial_reason"]
            rules = {"NONE": (100600, 0), "CUSTOMER_SCOPE_DENIED": (100602, 7),
                     "UNKNOWN_TOOL": (100603, 5), "IDENTITY_OVERRIDE": (100604, 7),
                     "SERVICE_PERMISSION_DENIED": (100605, 5), "MALFORMED_REQUEST": (100606, 4)}
            rule, level = rules[reason]
            if reason != "NONE":
                recent.append(clock.value)
                self.history[service] = recent
                if len(recent) == 5:
                    rule, level = 100610, 10
            reply = {"request_id": fields["request_id"], "rule_id": rule, "level": level,
                     "engine_utc": datetime.fromtimestamp(1793810000 + clock.value, timezone.utc).isoformat()}
            return alter(reply) if alter else reply
    return Session


def test_all_cases_acknowledged_timed_and_isolated():
    clock, sessions, records = Clock(), [], []
    retest.run_cases(factory(clock, sessions), records.append, clock=clock.now, sleep=clock.sleep)
    assert len(records) == 26
    assert len(sessions) == 6 and all(session.closed for session in sessions)
    assert len({r["session_id"] for r in records}) == 6
    assert len({r["request_id"] for r in records}) == 26
    assert all(r["acknowledged_monotonic"] > r["submitted_monotonic"] for r in records)
    outside = [r for r in records if r["case"] == "outside"]
    assert outside[-1]["submitted_monotonic"] - outside[-2]["acknowledged_monotonic"] >= 70
    assert sum(clock.sleeps) == pytest.approx(70)
    assert max(clock.sleeps) <= 1
    assert [r["rule_id"] for r in outside] == [100602] * 5
    assert [r["rule_id"] for r in records if r["case"] == "inside"] == [100602] * 4 + [100610]
    assert [r["rule_id"] for r in records if r["case"] == "different_service"] == [100602] * 5
    assert all("token" not in key for r in records for key in r)
    assert "balance" not in json.dumps(records)


@pytest.mark.parametrize("change", [
    lambda r: {**r, "request_id": "wrong-event"},
    lambda r: {**r, "engine_utc": "invalid"},
    lambda r: {**r, "level": True},
    lambda r: {**r, "rule_id": "100602"},
])
def test_unacknowledged_or_invalid_result_stops_before_next_event(change):
    clock, sessions, records = Clock(), [], []
    with pytest.raises(retest.RetestError):
        retest.run_cases(factory(clock, sessions, change), records.append, clock=clock.now, sleep=clock.sleep)
    assert sessions[0].calls == 1
    assert sessions[0].closed
    assert len(sessions) == 1


def test_wrong_rule_is_recorded_and_aborts():
    clock, sessions, records = Clock(), [], []
    with pytest.raises(retest.RetestError, match="Unexpected rule"):
        retest.run_cases(factory(clock, sessions, lambda r: {**r, "rule_id": 100610}),
                         records.append, clock=clock.now, sleep=clock.sleep)
    assert len(records) == 1 and records[0]["rule_id"] == 100610
    assert len(sessions) == 1


def test_slow_inside_window_is_inconclusive():
    clock, sessions, records = Clock(), [], []
    def slow(reply):
        clock.value += 51
        return reply
    with pytest.raises(retest.RetestError, match="inconclusive"):
        retest.run_cases(factory(clock, sessions, slow), records.append, clock=clock.now, sleep=clock.sleep)
    assert records[0]["timing_valid"] is False
    assert sessions[0].calls == 1


def test_frozen_engine_clock_cannot_pass_outside_case():
    clock, sessions, records = Clock(), [], []
    fixed = "2026-11-04T00:00:00+00:00"
    with pytest.raises(retest.RetestError, match="inconclusive"):
        retest.run_cases(factory(clock, sessions, lambda r: {**r, "engine_utc": fixed}),
                         records.append, clock=clock.now, sleep=clock.sleep)
    assert records[-1]["case"] == "outside"
    assert records[-1]["timing_valid"] is False
    assert len(sessions) == 5


def test_processing_timeout_stops_session():
    class Session:
        def __enter__(self): return self
        def __exit__(self, *args): self.closed = True
        def exchange(self, event): raise retest.RetestError("Timed out")
    instance = Session()
    with pytest.raises(retest.RetestError, match="Timed out"):
        retest.run_cases(lambda: instance, lambda result: pytest.fail("Unprocessed event recorded"))
    assert instance.closed


def test_default_is_plan_only(capsys):
    assert retest.main([]) == 0
    assert "No Docker execution" in capsys.readouterr().out


def test_missing_rules_fails_without_bridge(monkeypatch, capsys):
    def missing(*args, **kwargs):
        raise retest.subprocess.CalledProcessError(1, "docker")
    monkeypatch.setattr(retest.subprocess, "run", missing)
    assert retest.main(["--run-approved-retest"]) == 1
    assert "No deployment/restart" in capsys.readouterr().out


def test_bridge_has_no_token_or_raw_event_export():
    assert "client.process_log" in retest.BRIDGE
    assert "client.remove_session(client.last_token)" in retest.BRIDGE
    assert "reply['token'] != token" in retest.BRIDGE
    assert "'request_id': event_id" in retest.BRIDGE
    compile(retest.BRIDGE, "logtest-bridge", "exec")


@pytest.mark.parametrize("nested", [False, True])
def test_bridge_acknowledges_matching_event_and_cleans_session(monkeypatch, capsys, nested):
    instances = []
    class FakeClient:
        def __init__(self, **kwargs):
            self.calls = []
            self.cleaned = False
            self.last_token = ""
            instances.append(self)
        def process_log(self, text, token):
            self.calls.append(token)
            event_id = json.loads(text)["ai_security"]["request_id"]
            data = {"ai_security": {"request_id": event_id}} if nested else {"ai_security.request_id": event_id}
            self.last_token = "PRIVATE_SESSION_TOKEN"
            return {"token": self.last_token, "output": {
                "data": data, "timestamp": "2026-11-04T00:00:00+0000",
                "rule": {"id": "100602", "level": 7}}}
        def remove_session(self, token):
            assert token == self.last_token
            self.cleaned = True
            return True
        def remove_last_session(self):
            self.remove_session(self.last_token)  # Matches installed wrapper: returns None.
    events = [retest.synthetic_event(), retest.synthetic_event()]
    monkeypatch.setitem(sys.modules, "wazuh_logtest", SimpleNamespace(WazuhLogtest=FakeClient))
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(json.dumps({"event": e}) + "\n" for e in events)))
    exec(compile(retest.BRIDGE, "bridge", "exec"), {})
    output = capsys.readouterr().out
    assert "PRIVATE_SESSION_TOKEN" not in output
    replies = [json.loads(line) for line in output.splitlines()]
    assert [r["request_id"] for r in replies] == [e["ai_security"]["request_id"] for e in events]
    assert instances[0].calls == ["", "PRIVATE_SESSION_TOKEN"]
    assert instances[0].cleaned


def test_bridge_rejects_replaced_session(monkeypatch, capsys):
    class FakeClient:
        def __init__(self, **kwargs):
            self.count = 0
            self.last_token = ""
        def process_log(self, text, token):
            self.count += 1
            event_id = json.loads(text)["ai_security"]["request_id"]
            self.last_token = f"PRIVATE_TOKEN_{self.count}"
            return {"token": self.last_token, "output": {
                "data": {"ai_security.request_id": event_id},
                "timestamp": "2026-11-04T00:00:00Z", "rule": {"id": "100602", "level": 7}}}
        def remove_session(self, token):
            assert token == self.last_token
            return True
    monkeypatch.setitem(sys.modules, "wazuh_logtest", SimpleNamespace(WazuhLogtest=FakeClient))
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join(json.dumps({"event": retest.synthetic_event()}) + "\n" for _ in range(2))))
    exec(compile(retest.BRIDGE, "bridge", "exec"), {})
    output = capsys.readouterr().out
    assert "PRIVATE_TOKEN" not in output
    assert json.loads(output.splitlines()[-1]) == {"error": "logtest_request_failed"}


def test_bridge_real_cleanup_failure_still_fails(monkeypatch, capsys):
    class FakeClient:
        def __init__(self, **kwargs): self.last_token = ""
        def process_log(self, text, token):
            self.last_token = "PRIVATE_SESSION"
            return {"token": self.last_token, "output": {
                "data": {"ai_security.request_id": json.loads(text)["ai_security"]["request_id"]},
                "timestamp": "2026-11-04T00:00:00Z", "rule": {"id": "100602", "level": 7}}}
        def remove_session(self, token): return False
        def remove_last_session(self): self.remove_session(self.last_token)
    monkeypatch.setitem(sys.modules, "wazuh_logtest", SimpleNamespace(WazuhLogtest=FakeClient))
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"event": retest.synthetic_event()}) + "\n"))
    with pytest.raises(SystemExit) as caught:
        exec(compile(retest.BRIDGE, "bridge", "exec"), {})
    assert caught.value.code == 2
    assert "PRIVATE_SESSION" not in capsys.readouterr().out
