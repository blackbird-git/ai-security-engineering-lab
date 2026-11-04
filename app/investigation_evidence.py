"""Strict reader for the reviewed, synthetic indexed-alert artifact only."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'integrations/wazuh/evidence/2026-11-04-end-to-end-alerts.json'
SOURCE_SHA256 = '1a549128eaf3e3537e8c97e71c11c94c544bccddc796af9afdac5eb2c95e15ff'
SCHEMA = 'sanitized-indexed-alerts-v1'
MAX_EVIDENCE_BYTES = 16_384
MAX_RECORD_BYTES = 1_024
_METADATA = {
    'validation_date': '2026-11-04',
    'data_classification': 'SYNTHETIC SECURITY METADATA ONLY',
    'scope': 'actual application authorization -> JSONL -> manager local collection -> rule alert -> existing indexer',
    'model_proposals': 'offline synthetic fixtures; no live inference in this validation',
    'correlation_expiration': 'unverified; not a confirmed rule defect',
    'dashboard_ui': 'not inspected',
}
_FIELDS = {'event_type', 'request_id', 'outcome', 'denial_reason', 'service_id', 'tool_id',
           'event_timestamp', 'detection_timestamp', 'rule_id', 'alert_severity', 'location',
           'agent_id', 'index', 'indexed_verified'}
_RULES = {
    'CUSTOMER_SCOPE_DENIED': (100602, 7, 'get_customer_account'),
    'UNKNOWN_TOOL': (100603, 5, 'unknown'),
    'IDENTITY_OVERRIDE': (100604, 7, 'get_customer_account'),
    'SERVICE_PERMISSION_DENIED': (100605, 5, 'get_customer_transactions'),
    'MALFORMED_REQUEST': (100610, 10, 'none'),
}


class InvestigationError(Exception):
    """Fixed diagnostics only; never expose untrusted contents or exception details."""


def _pairs(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError
    return value


def strict_json(raw, limit):
    try:
        if type(raw) is str:
            raw = raw.encode('utf-8')
        if type(raw) is not bytes or not 0 < len(raw) <= limit:
            raise ValueError
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise InvestigationError('Invalid investigation input.') from None


@dataclass(frozen=True)
class Alert:
    evidence_id: str
    request_id: str
    event_timestamp: str
    detection_timestamp: str
    reason: str
    rule_id: int
    level: int


@dataclass(frozen=True)
class Evidence:
    schema: str
    digest: str
    alerts: tuple[Alert, ...]


def _time(value):
    if type(value) is not str or not re.fullmatch(r'2026-11-04T\d{2}:\d{2}:\d{2}\.\d{3}(Z|\+0000)', value):
        raise ValueError
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError
    return parsed


def parse_evidence(raw: bytes) -> Evidence:
    """Recognize legacy schema by its exact fields; also pin the reviewed artifact."""
    payload = strict_json(raw, MAX_EVIDENCE_BYTES)
    try:
        if type(payload) is not dict or set(payload) != set(_METADATA) | {'verified_denial_count', 'alerts'}:
            raise ValueError
        if any(type(payload[key]) is not str or payload[key] != value for key, value in _METADATA.items()):
            raise ValueError
        rows = payload['alerts']
        if type(rows) is not list or len(rows) != 5 or type(payload['verified_denial_count']) is not int or payload['verified_denial_count'] != len(rows):
            raise ValueError
        alerts = []
        for index, row in enumerate(rows, 1):
            if type(row) is not dict or set(row) != _FIELDS:
                raise ValueError
            if len(json.dumps(row).encode()) > MAX_RECORD_BYTES:
                raise ValueError
            if any(type(row[key]) is not str for key in _FIELDS - {'rule_id', 'alert_severity', 'indexed_verified'}):
                raise ValueError
            if type(row['rule_id']) is not int or type(row['alert_severity']) is not int or row['indexed_verified'] is not True:
                raise ValueError
            uid = UUID(row['request_id'])
            if uid.version != 4 or str(uid) != row['request_id']:
                raise ValueError
            if _time(row['detection_timestamp']) < _time(row['event_timestamp']):
                raise ValueError
            if row['event_type'] != 'tool_authorization' or row['outcome'] != 'denied' or row['service_id'] != 'service-01':
                raise ValueError
            if (row['rule_id'], row['alert_severity'], row['tool_id']) != _RULES.get(row['denial_reason']):
                raise ValueError
            if (row['agent_id'], row['index'], row['location']) != ('000', 'wazuh-alerts-4.x-2026.11.04', '/var/log/ai-security/security-events.jsonl'):
                raise ValueError
            alerts.append(Alert(f'E{index}', row['request_id'], row['event_timestamp'], row['detection_timestamp'],
                                row['denial_reason'], row['rule_id'], row['alert_severity']))
        if len({a.request_id for a in alerts}) != len(alerts):
            raise ValueError
        digest = hashlib.sha256(raw).hexdigest()
        if digest != SOURCE_SHA256:
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise InvestigationError('Invalid security evidence.') from None
    return Evidence(SCHEMA, digest, tuple(alerts))


def load_evidence() -> Evidence:
    """No caller/model-supplied path, raw log reader, or live Wazuh access."""
    try:
        descriptor = os.open(SOURCE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError
            raw = stream.read(MAX_EVIDENCE_BYTES + 1)
        return parse_evidence(raw)
    except (OSError, ValueError):
        raise InvestigationError('Unable to read security evidence.') from None
