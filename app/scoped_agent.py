"""Single-proposal agent harness; no chains, result feedback, or public endpoints."""

import argparse
from collections.abc import Callable
import json

from app.agent_tools import ServiceIdentity, ToolDenied, execute_tool
from app.ollama_client import OllamaClient, OllamaClientError
from app.secrets_boundary import contains_dummy_secret
from app.security_telemetry import SecurityTelemetry


_PROMPT = (
    "Propose exactly one read-only tool call as JSON, with only tool and arguments. "
    "Task: get the synthetic account for SYN-C001. "
    "Allowed schemas: get_customer_account arguments {customer_id: string}; "
    "get_customer_transactions arguments {customer_id: string, limit: integer 1..5}. "
    "Do not include identity or permissions. Do not make another request."
)


class AgentFailure(Exception):
    """Sanitized generation failure."""


def run_agent(service: ServiceIdentity, generate: Callable[[str], str], *,
              telemetry: SecurityTelemetry | None = None, request_id: str | None = None) -> dict:
    """Generate once, validate/authorize once; never send results back to the model."""
    if contains_dummy_secret(_PROMPT):
        raise AgentFailure("Agent generation failed.")
    try:
        proposal = generate(_PROMPT)
    except Exception:
        raise AgentFailure("Agent generation failed.") from None
    return execute_tool(service, proposal, telemetry=telemetry, request_id=request_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SYNTHETIC scoped agent lab; offline by default")
    parser.add_argument("--run-live", action="store_true", help="Opt in to one local Ollama proposal")
    args = parser.parse_args(argv)
    service = ServiceIdentity("svc-amber-account")
    if args.run_live:
        try:
            run_agent(service, OllamaClient().generate)
        except ToolDenied:
            print("LIVE_LOCAL_SYNTHETIC: proposal denied; no tool result disclosed.")
        except (AgentFailure, OllamaClientError, ValueError):
            print("LIVE_LOCAL_SYNTHETIC: generation failed.")
            return 1
        else:
            print("LIVE_LOCAL_SYNTHETIC: one authorized read executed; result withheld from output and model.")
        return 0
    cases = (
        ("authorized", {"tool": "get_customer_account", "arguments": {"customer_id": "SYN-C001"}}, True),
        ("cross_customer", {"tool": "get_customer_account", "arguments": {"customer_id": "SYN-C002"}}, False),
        ("unknown_tool", {"tool": "shell", "arguments": {"customer_id": "SYN-C001"}}, False),
        ("privilege_escalation", {"tool": "get_customer_account", "arguments": {"customer_id": "SYN-C002"},
                                   "identity": "svc-admin", "permissions": ["*"]}, False),
        ("service_permission", {"tool": "get_customer_transactions", "arguments": {"customer_id": "SYN-C001", "limit": 1}}, False),
    )
    print("OFFLINE_SYNTHETIC: mock proposals; no live model or financial output.")
    success = True
    for label, proposal, expected_allowed in cases:
        try:
            run_agent(service, lambda prompt: json.dumps(proposal))
        except ToolDenied:
            allowed = False
        else:
            allowed = True
        print(f"{label}: {'allowed' if allowed else 'denied'}")
        success = success and allowed == expected_allowed
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
