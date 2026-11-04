"""Strict allowlisted read-only tools with trusted fixture service policies."""

from dataclasses import dataclass
import json
from types import MappingProxyType

from app.financial_data import TrustedCaller, read_customer
from app.secrets_boundary import contains_dummy_secret
from app.security_telemetry import SecurityTelemetry, new_request_id, validate_request_id, TelemetryError


MAX_REQUEST_BYTES = 2048
MAX_RESULT_BYTES = 4096
ALLOWED_TOOLS = frozenset({"get_customer_account", "get_customer_transactions"})


@dataclass(frozen=True)
class ServiceIdentity:
    """Trusted harness context; not authentication or a Python security capability."""
    subject: str


@dataclass(frozen=True)
class _Policy:
    tools: frozenset[str]
    customers: frozenset[str]


_POLICIES = MappingProxyType({
    "svc-amber-account": _Policy(frozenset({"get_customer_account"}), frozenset({"SYN-C001"})),
    "svc-basil-transactions": _Policy(frozenset({"get_customer_transactions"}), frozenset({"SYN-C002"})),
    "svc-amber-reader": _Policy(ALLOWED_TOOLS, frozenset({"SYN-C001"})),
    "svc-no-access": _Policy(frozenset(), frozenset()),
})
_CUSTOMER_CALLERS = MappingProxyType({
    "SYN-C001": TrustedCaller("lab-amber"),
    "SYN-C002": TrustedCaller("lab-basil"),
    "SYN-C003": TrustedCaller("lab-coral"),
})


class ToolDenied(Exception):
    """Fixed denial excludes request text, identities, records, and secrets."""


def _deny():
    raise ToolDenied("Tool request denied.")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _deny()
        result[key] = value
    return result


def _invalid_constant(value):
    _deny()


def execute_tool(service: ServiceIdentity, model_request: str, *,
                 telemetry: SecurityTelemetry | None = None, request_id: str | None = None) -> dict:
    """Validate, authorize action AND customer, then execute exactly one read.

    Financial results are untrusted data and are never instructions or authority.
    """
    telemetry = telemetry if telemetry is not None else SecurityTelemetry()
    try:
        request_id = validate_request_id(request_id) if request_id is not None else new_request_id()
    except TelemetryError:
        raise ToolDenied("Tool request denied.") from None
    subject = service.subject if type(service) is ServiceIdentity and type(service.subject) is str else None
    safe_tool = "none"

    def record_decision(reason, event_type="tool_authorization"):
        try:
            return telemetry.emit(request_id=request_id, service_subject=subject,
                                  tool_id=safe_tool, reason=reason, event_type=event_type) is True
        except Exception:
            return False

    def deny(reason="MALFORMED_REQUEST", event_type="tool_authorization"):
        record_decision(reason, event_type)
        raise ToolDenied("Tool request denied.") from None

    if type(service) is not ServiceIdentity or type(service.subject) is not str:
        deny("UNKNOWN_SERVICE")
    policy = _POLICIES.get(service.subject)
    if policy is None:
        deny("UNKNOWN_SERVICE")
    if type(model_request) is not str:
        deny()
    try:
        if len(model_request.encode("utf-8")) > MAX_REQUEST_BYTES or contains_dummy_secret(model_request):
            _deny()
        request = json.loads(model_request, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, UnicodeError, RecursionError, ToolDenied):
        deny()
    authority_fields = {"identity", "service", "subject", "caller", "permissions", "scope", "role"}
    if type(request) is dict:
        candidate = request.get("tool")
        if type(candidate) is str:
            safe_tool = candidate if candidate in ALLOWED_TOOLS else "unknown"
        arguments_candidate = request.get("arguments")
        if authority_fields.intersection(request) or (
            type(arguments_candidate) is dict and authority_fields.intersection(arguments_candidate)
        ):
            deny("IDENTITY_OVERRIDE")
    if type(request) is not dict or set(request) != {"tool", "arguments"}:
        deny()
    tool, arguments = request["tool"], request["arguments"]
    if type(tool) is not str:
        deny()
    if tool not in ALLOWED_TOOLS:
        deny("UNKNOWN_TOOL")
    if tool not in policy.tools:
        deny("SERVICE_PERMISSION_DENIED")
    expected = {"customer_id"} if tool == "get_customer_account" else {"customer_id", "limit"}
    if type(arguments) is not dict or set(arguments) != expected:
        deny()
    customer = arguments["customer_id"]
    if type(customer) is not str:
        deny()
    if customer not in policy.customers or customer not in _CUSTOMER_CALLERS:
        deny("CUSTOMER_SCOPE_DENIED")
    if tool == "get_customer_transactions" and (
        type(arguments["limit"]) is not int or not 1 <= arguments["limit"] <= 5
    ):
        deny()
    # Enabled storage must succeed BEFORE any data read; failure never grants access.
    if not record_decision("NONE"):
        raise ToolDenied("Tool request denied.")
    # Scope checked above; a trusted fixed mapping supplies the data-layer caller.
    # The underlying reader independently verifies that caller's customer scope.
    try:
        record = read_customer(_CUSTOMER_CALLERS[customer], customer)
        result = {"data_label": record.data_label, "customer_id": record.customer_id}
        if tool == "get_customer_account":
            result["balance_cents"] = record.balance_cents
        else:
            result["transactions"] = [
                {"transaction_id": item.transaction_id, "amount_cents": item.amount_cents,
                 "description": item.description}
                for item in record.transactions[:arguments["limit"]]
            ]
        encoded = json.dumps(result, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_RESULT_BYTES or contains_dummy_secret(encoded):
            deny("RESULT_REJECTED", "tool_result")
    except ToolDenied:
        raise
    except Exception:
        deny("RESULT_REJECTED", "tool_result")
    return result
