"""Allowlisted authorization events and opt-in, bounded local JSONL storage."""

from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID, uuid4


SCHEMA_VERSION = "1.0"
MAX_EVENT_BYTES = 1024
MAX_FILE_BYTES = 1_048_576
LOG_DIRECTORY = Path(__file__).resolve().parents[1] / "local" / "telemetry"
_SERVICE_IDS = {
    "svc-amber-account": "service-01", "svc-basil-transactions": "service-02",
    "svc-amber-reader": "service-03", "svc-no-access": "service-04",
}
_TOOLS = {"get_customer_account", "get_customer_transactions", "unknown", "none"}
_REASONS = {
    "NONE", "CUSTOMER_SCOPE_DENIED", "UNKNOWN_TOOL", "IDENTITY_OVERRIDE",
    "SERVICE_PERMISSION_DENIED", "MALFORMED_REQUEST", "UNKNOWN_SERVICE",
    "RESULT_REJECTED",
}
_KEYS = {"timestamp", "schema_version", "event_type", "outcome", "severity",
         "request_id", "service_id", "tool_id", "denial_reason"}


class TelemetryError(Exception):
    """Fixed diagnostic; no path, raw identity, or event payload."""


def validate_request_id(value: str) -> str:
    try:
        if type(value) is not str or str(UUID(value)) != value or UUID(value).version != 4:
            raise ValueError
    except (ValueError, AttributeError):
        raise TelemetryError("Invalid telemetry context.") from None
    return value


def make_event(*, request_id: str, service_subject: str | None, tool_id: str,
               reason: str, event_type: str = "tool_authorization") -> dict:
    """Called by trusted code; never accepts a free-text message or raw payload."""
    if type(service_subject) is not str:
        service_subject = None
    outcome = "allowed" if reason == "NONE" else "denied"
    event = {"ai_security": {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "schema_version": SCHEMA_VERSION, "event_type": event_type,
        "outcome": outcome, "severity": "info" if outcome == "allowed" else "medium",
        "request_id": validate_request_id(request_id),
        "service_id": _SERVICE_IDS.get(service_subject, "service-unknown"),
        "tool_id": tool_id, "denial_reason": reason,
    }}
    serialize_event(event)
    return event


def serialize_event(event: dict) -> bytes:
    """Validate an exact schema before exporting a single JSONL line."""
    try:
        if type(event) is not dict or set(event) != {"ai_security"}:
            raise ValueError
        fields = event["ai_security"]
        if type(fields) is not dict or set(fields) != _KEYS or any(type(v) is not str for v in fields.values()):
            raise ValueError
        if fields["schema_version"] != SCHEMA_VERSION or fields["event_type"] not in {"tool_authorization", "tool_result"}:
            raise ValueError
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", fields["timestamp"]):
            raise ValueError
        datetime.fromisoformat(fields["timestamp"].replace("Z", "+00:00"))
        validate_request_id(fields["request_id"])
        if fields["service_id"] not in {*_SERVICE_IDS.values(), "service-unknown"} or fields["tool_id"] not in _TOOLS:
            raise ValueError
        if fields["denial_reason"] not in _REASONS:
            raise ValueError
        allowed = fields["denial_reason"] == "NONE"
        if fields["outcome"] != ("allowed" if allowed else "denied") or fields["severity"] != ("info" if allowed else "medium"):
            raise ValueError
        if fields["event_type"] == "tool_result" and fields["denial_reason"] != "RESULT_REJECTED":
            raise ValueError
        line = (json.dumps(event, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        if len(line) > MAX_EVENT_BYTES:
            raise ValueError
    except (ValueError, TypeError, KeyError, TelemetryError):
        raise TelemetryError("Invalid security event.") from None
    return line


class JsonlWriter:
    """Local-only append sink; refuses rotation, unsafe files, and over-capacity logs."""

    def __init__(self, path: str | Path, *, max_bytes: int = MAX_FILE_BYTES):
        path = Path(path).absolute()
        if path.parent != LOG_DIRECTORY or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}\.jsonl", path.name):
            raise TelemetryError("Invalid telemetry configuration.")
        if type(max_bytes) is not int or not MAX_EVENT_BYTES <= max_bytes <= MAX_FILE_BYTES:
            raise TelemetryError("Invalid telemetry configuration.")
        self.path, self.max_bytes = path, max_bytes

    def write(self, event: dict) -> bool:
        """False on any storage failure; callers must withhold authorized results."""
        fd = directory = None
        try:
            line = serialize_event(event)
            directory = os.open(LOG_DIRECTORY.parents[1], os.O_RDONLY | os.O_DIRECTORY)
            # Traverse/create only fixed repo-relative directories, refusing symlinks.
            for component in ("local", "telemetry"):
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory)
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(self.path.name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=directory)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                return False
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if os.fstat(fd).st_size + len(line) > self.max_bytes:
                return False
            return os.write(fd, line) == len(line)
        except Exception:
            return False
        finally:
            for descriptor in (fd, directory):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass


class SecurityTelemetry:
    """No sink by default: validate events in memory without writing any files."""

    def __init__(self, writer: JsonlWriter | None = None):
        self.writer = writer

    def emit(self, *, request_id: str, service_subject: str | None, tool_id: str,
             reason: str, event_type: str = "tool_authorization") -> bool:
        try:
            event = make_event(request_id=request_id, service_subject=service_subject,
                               tool_id=tool_id, reason=reason, event_type=event_type)
            return True if self.writer is None else self.writer.write(event) is True
        except Exception:
            return False


def new_request_id() -> str:
    return str(uuid4())
