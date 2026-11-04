"""SYNTHETIC ONLY: immutable fictional fixtures and read-only authorization."""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class Transaction:
    transaction_id: str
    amount_cents: int
    description: str


@dataclass(frozen=True)
class CustomerRecord:
    customer_id: str
    fictional_name: str
    balance_cents: int
    transactions: tuple[Transaction, ...]
    data_label: str = "SYNTHETIC - NOT REAL FINANCIAL DATA"


_RECORDS = MappingProxyType({
    "SYN-C001": CustomerRecord("SYN-C001", "Fictional Amber Finch", 120_000,
        (Transaction("SYN-T001", 25_000, "Synthetic deposit"),)),
    "SYN-C002": CustomerRecord("SYN-C002", "Fictional Basil Cloud", 230_000,
        (Transaction("SYN-T002", -3_000, "Synthetic purchase"),)),
    "SYN-C003": CustomerRecord("SYN-C003", "Fictional Coral Meadow", 340_000,
        (Transaction("SYN-T003", 10_000, "Synthetic transfer"),)),
})
_CUSTOMER_BY_SUBJECT = MappingProxyType({
    "lab-amber": "SYN-C001", "lab-basil": "SYN-C002", "lab-coral": "SYN-C003",
})


@dataclass(frozen=True)
class TrustedCaller:
    """Internal caller context supplied by trusted code, never parsed from model text.

    This object is not an authentication mechanism or a secure Python capability.
    The CLI uses a fixed fixture identity; future services must authenticate first.
    """

    subject: str


class AccessDenied(Exception):
    """Generic denial with no financial data or identity details."""


def read_customer(caller: TrustedCaller, customer_id: str) -> CustomerRecord:
    """Authorize action and customer scope before reading an immutable record."""
    if (
        type(caller) is not TrustedCaller
        or type(caller.subject) is not str
        or type(customer_id) is not str
        or _CUSTOMER_BY_SUBJECT.get(caller.subject) != customer_id
        or customer_id not in _RECORDS
    ):
        raise AccessDenied("Customer access denied.")
    return _RECORDS[customer_id]
