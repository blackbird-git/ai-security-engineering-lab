"""Offline security regression tests for scoped tools and single-step orchestration."""

from dataclasses import FrozenInstanceError, replace
import json
import socket

import pytest

from app import agent_tools as tools
from app import scoped_agent as agent
from app.financial_data import AccessDenied
from app.main import app
from app.secrets_boundary import _DUMMY_SECRET


def request(tool="get_customer_account", customer="SYN-C001", **extra):
    arguments = {"customer_id": customer}
    arguments.update(extra)
    return json.dumps({"tool": tool, "arguments": arguments})


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Tests must not use network")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.mark.parametrize("subject,tool,customer,allowed", [
    ("svc-amber-account", "get_customer_account", "SYN-C001", True),
    ("svc-amber-account", "get_customer_transactions", "SYN-C001", False),
    ("svc-amber-reader", "get_customer_account", "SYN-C001", True),
    ("svc-amber-reader", "get_customer_transactions", "SYN-C001", True),
    ("svc-amber-reader", "get_customer_account", "SYN-C002", False),
    ("svc-basil-transactions", "get_customer_transactions", "SYN-C002", True),
    ("svc-basil-transactions", "get_customer_account", "SYN-C002", False),
    ("svc-basil-transactions", "get_customer_transactions", "SYN-C001", False),
    ("svc-no-access", "get_customer_account", "SYN-C001", False),
    ("unknown", "get_customer_account", "SYN-C001", False),
])
def test_service_and_customer_policy(subject, tool, customer, allowed):
    payload = request(tool, customer, **({"limit": 1} if tool.endswith("transactions") else {}))
    identity = tools.ServiceIdentity(subject)
    if not allowed:
        with pytest.raises(tools.ToolDenied):
            tools.execute_tool(identity, payload)
        return
    result = tools.execute_tool(identity, payload)
    assert result["customer_id"] == customer
    assert "SYNTHETIC" in result["data_label"]
    assert len(json.dumps(result).encode()) <= tools.MAX_RESULT_BYTES
    if tool.endswith("account"):
        assert set(result) == {"customer_id", "data_label", "balance_cents"}
    else:
        assert len(result["transactions"]) <= 1
        assert "balance_cents" not in result


@pytest.mark.parametrize("identity", [None, {}, "svc-amber-reader", tools.ServiceIdentity(""), tools.ServiceIdentity([])])
def test_bad_identity(identity):
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(identity, request())


@pytest.mark.parametrize("payload", [
    None, {}, [], "", "not json", "null", "[]", "1", '"text"', "{" * 2049,
    "[" * 1500, "\ud800", "é" * 1025,
    '{"tool":"get_customer_account","tool":"get_customer_transactions","arguments":{"customer_id":"SYN-C001"}}',
    '{"tool":"get_customer_account","arguments":{"customer_id":"SYN-C002","customer_id":"SYN-C001"}}',
    '{"tool":"get_customer_transactions","arguments":{"customer_id":"SYN-C001","limit":NaN}}',
    '{"tool":"get_customer_transactions","arguments":{"customer_id":"SYN-C001","limit":Infinity}}',
    '{"tool":[],"arguments":{}}', '{"tool":null,"arguments":{}}',
    '{"tool":"get_customer_account","arguments":[]}',
    '{"tool":"get_customer_account"}',
])
def test_malformed_requests_never_execute(payload, monkeypatch):
    monkeypatch.setattr(tools, "read_customer", lambda *args: pytest.fail("Reader called before validation"))
    with pytest.raises(tools.ToolDenied) as caught:
        tools.execute_tool(tools.ServiceIdentity("svc-amber-reader"), payload)
    assert str(caught.value) == "Tool request denied."


@pytest.mark.parametrize("tool", ["shell", "python", "get_secret", "__import__", "GET_CUSTOMER_ACCOUNT", "get_customer_account ", "get_customer_account; id"])
def test_unknown_tools(tool, monkeypatch):
    monkeypatch.setattr(tools, "read_customer", lambda *args: pytest.fail("Unknown tool executed"))
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-reader"), request(tool))


@pytest.mark.parametrize("customer", [None, [], {}, True, 1, "", "../SYN-C001", "SYN-C003", "SYN-C001 "])
def test_invalid_or_out_of_scope_customer(customer):
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-reader"), request(customer=customer))


@pytest.mark.parametrize("limit", [True, False, None, "1", 1.0, [], {}, 0, -1, 6, 10**100])
def test_transaction_limits(limit):
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-reader"), request("get_customer_transactions", limit=limit))


@pytest.mark.parametrize("field", ["identity", "service", "subject", "caller", "permissions", "scope", "role", "tools", "secret", "command"])
@pytest.mark.parametrize("location", ["top", "arguments"])
def test_authority_override_denied(field, location, monkeypatch):
    payload = json.loads(request())
    target = payload if location == "top" else payload["arguments"]
    target[field] = "admin"
    monkeypatch.setattr(tools, "read_customer", lambda *args: pytest.fail("Override reached data layer"))
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), json.dumps(payload))


def test_missing_limit_and_unexpected_account_limit():
    for payload in (request("get_customer_transactions"), request(limit=1)):
        with pytest.raises(tools.ToolDenied):
            tools.execute_tool(tools.ServiceIdentity("svc-amber-reader"), payload)


def test_service_permission_denied_before_reader(monkeypatch):
    monkeypatch.setattr(tools, "read_customer", lambda *args: pytest.fail("Service denial occurred too late"))
    with pytest.raises(tools.ToolDenied):
        tools.execute_tool(tools.ServiceIdentity("svc-amber-account"), request("get_customer_transactions", limit=1))


def test_data_layer_authorization_retained(monkeypatch):
    def denied(caller, customer):
        assert caller.subject == "lab-amber"
        assert customer == "SYN-C001"
        raise AccessDenied("PRIVATE_DETAIL")
    monkeypatch.setattr(tools, "read_customer", denied)
    with pytest.raises(tools.ToolDenied) as caught:
        tools.execute_tool(tools.ServiceIdentity("svc-amber-reader"), request())
    assert str(caught.value) == "Tool request denied."
    assert caught.value.__suppress_context__


def test_result_size_and_secret_export_guards(monkeypatch):
    original = tools.read_customer
    record = original(tools._CUSTOMER_CALLERS["SYN-C001"], "SYN-C001")
    for label in ("x" * 5000, _DUMMY_SECRET):
        monkeypatch.setattr(tools, "read_customer", lambda *args: replace(record, data_label=label))
        with pytest.raises(tools.ToolDenied) as caught:
            tools.execute_tool(tools.ServiceIdentity("svc-amber-reader"), request())
        assert str(caught.value) == "Tool request denied."


def test_result_is_detached_from_fixtures():
    service = tools.ServiceIdentity("svc-amber-reader")
    result = tools.execute_tool(service, request("get_customer_transactions", limit=5))
    result["transactions"][0]["amount_cents"] = 0
    assert tools.execute_tool(service, request("get_customer_transactions", limit=5))["transactions"][0]["amount_cents"] == 25000
    with pytest.raises(FrozenInstanceError):
        service.subject = "svc-admin"


def test_single_generation_no_feedback_or_secret(caplog):
    prompts = []
    def model(prompt):
        prompts.append(prompt)
        return request()
    result = agent.run_agent(tools.ServiceIdentity("svc-amber-account"), model)
    assert result["balance_cents"] == 120000
    assert len(prompts) == 1
    assert _DUMMY_SECRET not in prompts[0]
    assert "120000" not in prompts[0]
    assert _DUMMY_SECRET not in json.dumps(result)
    assert caplog.text == ""


def test_chains_and_secret_requests_denied():
    for payload in (json.dumps([json.loads(request()), json.loads(request())]), request(customer=_DUMMY_SECRET)):
        with pytest.raises(tools.ToolDenied):
            agent.run_agent(tools.ServiceIdentity("svc-amber-reader"), lambda prompt: payload)


def test_generation_failure_sanitized():
    def model(prompt):
        raise RuntimeError(_DUMMY_SECRET)
    with pytest.raises(agent.AgentFailure) as caught:
        agent.run_agent(tools.ServiceIdentity("svc-amber-account"), model)
    assert str(caught.value) == "Agent generation failed."
    assert caught.value.__suppress_context__


def test_prompt_secret_guard(monkeypatch):
    monkeypatch.setattr(agent, "_PROMPT", _DUMMY_SECRET)
    with pytest.raises(agent.AgentFailure):
        agent.run_agent(tools.ServiceIdentity("svc-amber-account"), lambda prompt: pytest.fail("Secret exported"))


def test_offline_cli(monkeypatch, capsys):
    monkeypatch.setattr(agent, "OllamaClient", lambda: pytest.fail("Offline CLI created live client"))
    assert agent.main([]) == 0
    output = capsys.readouterr().out
    assert "authorized: allowed" in output
    for label in ("cross_customer", "unknown_tool", "privilege_escalation", "service_permission"):
        assert f"{label}: denied" in output
    assert _DUMMY_SECRET not in output
    assert "120000" not in output


@pytest.mark.parametrize("proposal,expected", [(request(), "authorized read"), (request(customer="SYN-C002"), "denied")])
def test_live_cli_with_mock_only(monkeypatch, capsys, proposal, expected):
    class FakeClient:
        def generate(self, prompt):
            return proposal
    monkeypatch.setattr(agent, "OllamaClient", FakeClient)
    assert agent.main(["--run-live"]) == 0
    assert expected in capsys.readouterr().out


def test_live_cli_failure_mock(monkeypatch, capsys):
    class FakeClient:
        def generate(self, prompt):
            raise RuntimeError(_DUMMY_SECRET)
    monkeypatch.setattr(agent, "OllamaClient", FakeClient)
    assert agent.main(["--run-live"]) == 1
    assert _DUMMY_SECRET not in capsys.readouterr().out


def test_api_remains_health_only():
    assert [(route.path, route.methods) for route in app.routes] == [("/healthz", {"GET"})]
