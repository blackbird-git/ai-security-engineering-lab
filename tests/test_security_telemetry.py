"""Offline telemetry schema, privacy, authorization, and bounded storage tests."""

from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import stat
from uuid import uuid4
import xml.etree.ElementTree as ET

import pytest

from app import agent_tools as tools
from app import security_telemetry as security
from app.scoped_agent import run_agent
from app.secrets_boundary import _DUMMY_SECRET
from app.telemetry_demo import main


def proposal(tool="get_customer_account", customer="SYN-C001", **extra):
    return json.dumps({"tool": tool, "arguments": {"customer_id": customer}, **extra})


def event():
    return security.make_event(request_id=str(uuid4()), service_subject="svc-amber-account",
                               tool_id="get_customer_account", reason="NONE")


class Capture:
    def __init__(self):
        self.events = []
    def write(self, value):
        self.events.append(deepcopy(value))
        return True


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("No network allowed")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def log_root(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    root = repo / "local" / "telemetry"
    monkeypatch.setattr(security, "LOG_DIRECTORY", root)
    return root


@pytest.mark.parametrize("payload,reason,tool", [
    (proposal(), "NONE", "get_customer_account"),
    (proposal(customer="SYN-C002"), "CUSTOMER_SCOPE_DENIED", "get_customer_account"),
    (proposal(tool="PRIVATE_UNRESTRICTED_SHELL"), "UNKNOWN_TOOL", "unknown"),
    (proposal(identity="PRIVATE_IDENTITY"), "IDENTITY_OVERRIDE", "get_customer_account"),
    (proposal(tool="get_customer_transactions"), "SERVICE_PERMISSION_DENIED", "get_customer_transactions"),
    ("PRIVATE_MALFORMED_PROMPT", "MALFORMED_REQUEST", "none"),
    ("x" * 2049, "MALFORMED_REQUEST", "none"),
    ('{"tool":"get_customer_account","arguments":{"customer_id":"SYN-C001","role":"admin"}}', "IDENTITY_OVERRIDE", "get_customer_account"),
    ('{"tool":"get_customer_account","tool":"shell","arguments":{}}', "MALFORMED_REQUEST", "none"),
])
def test_trusted_decisions_single_event(payload, reason, tool, caplog):
    capture = Capture()
    context = str(uuid4())
    def call():
        return run_agent(tools.ServiceIdentity("svc-amber-account"), lambda prompt: payload,
                         telemetry=security.SecurityTelemetry(capture), request_id=context)
    if reason == "NONE":
        assert call()["balance_cents"] == 120000
    else:
        with pytest.raises(tools.ToolDenied):
            call()
    assert len(capture.events) == 1
    fields = capture.events[0]["ai_security"]
    assert fields["request_id"] == context
    assert fields["denial_reason"] == reason
    assert fields["tool_id"] == tool
    assert fields["service_id"] == "service-01"
    serialized = security.serialize_event(capture.events[0]).decode()
    for forbidden in ("PRIVATE", "SYN-C", "lab-amber", "svc-amber", "120000", "transactions\":", "Fictional", _DUMMY_SECRET):
        assert forbidden not in serialized
    assert caplog.text == ""


def test_model_claim_cannot_forge_event_or_correlation():
    capture = Capture()
    text = proposal(event_type="attack_succeeded", request_id="PRIVATE", severity="high")
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), text,
                           telemetry=security.SecurityTelemetry(capture))
    fields = capture.events[0]["ai_security"]
    assert fields["denial_reason"] == "MALFORMED_REQUEST"
    assert fields["event_type"] == "tool_authorization"
    assert fields["request_id"] != "PRIVATE"


def test_unknown_service_is_not_logged_raw():
    capture = Capture()
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity(_DUMMY_SECRET), proposal(),
                           telemetry=security.SecurityTelemetry(capture))
    assert capture.events[0]["ai_security"]["service_id"] == "service-unknown"
    assert _DUMMY_SECRET not in json.dumps(capture.events)


@pytest.mark.parametrize("field,value", [
    ("timestamp", "2026-11-04T00:00:00+01:00"), ("timestamp", "2026-99-04T00:00:00.000Z"),
    ("schema_version", "2.0"), ("event_type", "attack_succeeded"),
    ("outcome", "granted"), ("severity", "critical"), ("request_id", "raw-token"),
    ("request_id", str(uuid4()).upper()), ("service_id", "raw-customer-name"),
    ("tool_id", "shell"), ("denial_reason", "raw-secret"), ("severity", None),
])
def test_field_validation(field, value):
    value_event = event()
    value_event["ai_security"][field] = value
    with pytest.raises(security.TelemetryError) as caught:
        security.serialize_event(value_event)
    assert str(caught.value) == "Invalid security event."


def test_exact_schema_and_size(monkeypatch):
    for extra in ("prompt", "response", "balance_cents", "transactions", "token", "name"):
        value_event = event()
        value_event["ai_security"][extra] = "PRIVATE"
        with pytest.raises(security.TelemetryError):
            security.serialize_event(value_event)
    line = security.serialize_event(event())
    assert len(line) <= security.MAX_EVENT_BYTES
    assert line.count(b"\n") == 1
    monkeypatch.setattr(security, "MAX_EVENT_BYTES", len(line) - 1)
    with pytest.raises(security.TelemetryError):
        security.serialize_event(json.loads(line))


def test_default_no_files(log_root):
    tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), proposal())
    assert not log_root.exists()


def test_explicit_writer_json_permissions_and_cap(log_root):
    writer = security.JsonlWriter(log_root / "test.jsonl", max_bytes=1024)
    accepted = 0
    while writer.write(event()):
        accepted += 1
        assert accepted < 10
    lines = writer.path.read_bytes().splitlines()
    assert len(lines) == accepted
    assert writer.path.stat().st_size <= 1024
    assert stat.S_IMODE(writer.path.stat().st_mode) == 0o600
    for line in lines:
        security.serialize_event(json.loads(line))


@pytest.mark.parametrize("name", ["../outside.jsonl", "../telemetry/../bad.jsonl", "bad.log", "SECRET.jsonl"])
def test_unsafe_config_rejected(log_root, name):
    with pytest.raises(security.TelemetryError):
        security.JsonlWriter(log_root / name)


def test_symlinks_rejected(log_root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    log_root.parent.symlink_to(outside, target_is_directory=True)
    assert not security.JsonlWriter(log_root / "test.jsonl").write(event())
    assert list(outside.iterdir()) == []


def test_file_symlink_and_hardlink_rejected(log_root, tmp_path):
    log_root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("untouched")
    target = log_root / "test.jsonl"
    target.symlink_to(outside)
    assert not security.JsonlWriter(target).write(event())
    target.unlink()
    os.link(outside, target)
    assert not security.JsonlWriter(target).write(event())
    assert outside.read_text() == "untouched"


def test_existing_insecure_file_rejected(log_root):
    log_root.mkdir(parents=True)
    target = log_root / "test.jsonl"
    target.touch(mode=0o644)
    assert not security.JsonlWriter(target).write(event())
    assert target.stat().st_size == 0


@pytest.mark.parametrize("failure", ["false", "raise"])
def test_storage_failure_never_permits_read(failure, monkeypatch):
    class Broken:
        def write(self, value):
            if failure == "raise":
                raise OSError("PRIVATE_SECRET_PATH")
            return False
    monkeypatch.setattr(tools, "read_customer", lambda *args: pytest.fail("Read on telemetry failure"))
    for payload in (proposal(), proposal(customer="SYN-C002")):
        with pytest.raises(tools.ToolDenied) as caught:
            tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), payload,
                               telemetry=security.SecurityTelemetry(Broken()))
        assert str(caught.value) == "Tool request denied."


@pytest.mark.parametrize("operation", ["write", "flock"])
def test_io_error_sanitized(operation, log_root, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("PRIVATE_SECRET")
    monkeypatch.setattr(security.os if operation == "write" else security.fcntl, operation, fail)
    assert not security.JsonlWriter(log_root / "test.jsonl").write(event())


def test_capacity_exhaustion_denies_before_read(log_root, monkeypatch):
    writer = security.JsonlWriter(log_root / "test.jsonl", max_bytes=1024)
    while writer.write(event()):
        pass
    monkeypatch.setattr(tools, "read_customer", lambda *args: pytest.fail("Read after capacity reached"))
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), proposal(),
                           telemetry=security.SecurityTelemetry(writer))


def test_short_write_and_fifo_fail_safely(log_root, monkeypatch):
    writer = security.JsonlWriter(log_root / "test.jsonl")
    monkeypatch.setattr(security.os, "write", lambda *args: 0)
    assert not writer.write(event())
    fifo = log_root / "fifo.jsonl"
    os.mkfifo(fifo, mode=0o600)
    assert not security.JsonlWriter(fifo).write(event())


def test_unexpected_emitter_failure_never_reads(monkeypatch):
    class Broken:
        def emit(self, **kwargs):
            raise RuntimeError("PRIVATE")
    monkeypatch.setattr(tools, "read_customer", lambda *args: pytest.fail("Telemetry failure bypass"))
    with pytest.raises(tools.ToolDenied) as caught:
        tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), proposal(), telemetry=Broken())
    assert str(caught.value) == "Tool request denied."


@pytest.mark.parametrize("max_bytes", [True, 0, 1023, security.MAX_FILE_BYTES + 1])
def test_invalid_storage_cap(log_root, max_bytes):
    with pytest.raises(security.TelemetryError):
        security.JsonlWriter(log_root / "test.jsonl", max_bytes=max_bytes)


def test_result_rejection_shares_correlation(monkeypatch):
    original = tools.read_customer
    record = original(tools._CUSTOMER_CALLERS["SYN-C001"], "SYN-C001")
    monkeypatch.setattr(tools, "read_customer", lambda *args: replace(record, data_label=_DUMMY_SECRET))
    capture = Capture()
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), proposal(),
                           telemetry=security.SecurityTelemetry(capture))
    fields = [value["ai_security"] for value in capture.events]
    assert [value["denial_reason"] for value in fields] == ["NONE", "RESULT_REJECTED"]
    assert len({value["request_id"] for value in fields}) == 1
    assert fields[1]["event_type"] == "tool_result"
    assert _DUMMY_SECRET not in json.dumps(capture.events)


def test_generated_ids_unique_and_invalid_ids_denied():
    capture = Capture()
    for _ in range(2):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), proposal(), telemetry=security.SecurityTelemetry(capture))
    assert len({e["ai_security"]["request_id"] for e in capture.events}) == 2
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), proposal(), request_id="PRIVATE")


def test_cli_default_and_explicit_logging(log_root, capsys):
    assert main([]) == 0
    assert "storage: disabled" in capsys.readouterr().out
    assert not log_root.exists()
    assert main(["--log-file", str(log_root / "test.jsonl")]) == 0
    output = capsys.readouterr().out
    assert "storage: enabled" in output
    assert "customer_scope: denied" in output
    assert len((log_root / "test.jsonl").read_text().splitlines()) == 6
    assert main(["--log-file", "/outside/private.jsonl"]) == 1


def test_wazuh_artifact_structure_and_sample_schema():
    root = Path(__file__).resolve().parents[1] / "integrations" / "wazuh"
    rules = ET.parse(root / "ai_security_rules.xml").getroot()
    assert rules.tag == "group"
    ids = {node.attrib["id"] for node in rules.findall("rule")}
    assert len(ids) == len(rules.findall("rule")) == 8
    assert rules.find("rule/decoded_as").text == "json"
    repeated = rules.find("rule[@id='100610']")
    assert repeated.find("if_sid").text == "100600"
    assert repeated.find("field[@name='ai_security.outcome']").text == "^denied$"
    assert repeated.find("same_field").text == "ai_security.service_id"
    assert repeated.find("if_matched_group").text == "ai_authorization_failure"
    collector = ET.parse(root / "localfile.example.xml").getroot()
    assert collector.find("localfile/log_format").text == "json"
    assert collector.find("localfile/location").text == "/var/log/ai-security/security-events.jsonl"
    for line in (root / "samples" / "security-events.jsonl").read_text().splitlines():
        security.serialize_event(json.loads(line))
