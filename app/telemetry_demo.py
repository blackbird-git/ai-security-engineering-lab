"""Actual offline authorization scenarios with optional local-only JSONL storage."""

import argparse
from collections import Counter
import json

from app.agent_tools import ServiceIdentity, ToolDenied
from app.scoped_agent import run_agent
from app.security_telemetry import JsonlWriter, SecurityTelemetry, TelemetryError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic authorization telemetry")
    parser.add_argument("--log-file", help="Explicitly enable JSONL under repository/local/telemetry/")
    args = parser.parse_args(argv)
    try:
        writer = JsonlWriter(args.log_file) if args.log_file else None
    except (TelemetryError, ValueError, TypeError):
        print("Telemetry configuration rejected.")
        return 1

    class ObservedTelemetry(SecurityTelemetry):
        def __init__(self):
            super().__init__(writer)
            self.counts = Counter()
            self.failed = False

        def emit(self, **fields):
            ok = super().emit(**fields)
            self.counts[fields["reason"]] += 1
            self.failed = self.failed or not ok
            return ok

    telemetry = ObservedTelemetry()
    service = ServiceIdentity("svc-amber-account")
    account = {"tool": "get_customer_account", "arguments": {"customer_id": "SYN-C001"}}
    cases = (
        ("authorized", json.dumps(account), True),
        ("customer_scope", json.dumps({**account, "arguments": {"customer_id": "SYN-C002"}}), False),
        ("unknown_tool", json.dumps({**account, "tool": "shell"}), False),
        ("identity_override", json.dumps({**account, "identity": "svc-admin"}), False),
        ("service_permission", json.dumps({"tool": "get_customer_transactions", "arguments": {"customer_id": "SYN-C001", "limit": 1}}), False),
        ("malformed", "not-json", False),
    )
    success = True
    for label, proposal, expected in cases:
        try:
            run_agent(service, lambda prompt: proposal, telemetry=telemetry)
        except ToolDenied:
            allowed = False
        else:
            allowed = True
        print(f"{label}: {'allowed' if allowed else 'denied'}")
        success = success and allowed == expected
    print("events: " + json.dumps(dict(sorted(telemetry.counts.items())), sort_keys=True))
    print("storage: " + ("failed" if telemetry.failed else "enabled" if writer else "disabled"))
    return 0 if success and not telemetry.failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
