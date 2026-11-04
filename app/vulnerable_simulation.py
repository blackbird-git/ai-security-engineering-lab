"""Opt-in illustrative outcome only; isolated from data access and inference.

No financial reader, credentials, tools, filesystem access, or network operations.
This prints a hypothetical failure rather than implementing an unsafe data path.
"""


def simulate_vulnerable_outcome(*, opt_in: bool = False) -> str:
    if opt_in is not True:
        raise PermissionError("Vulnerable simulation requires explicit opt-in.")
    return (
        "VULNERABLE SIMULATION ONLY: assume the same injected document changes "
        "the model proposal to SYN-C002. A hypothetical dispatcher trusting that "
        "scope would disclose another SYNTHETIC customer's records. "
        "No unauthorized read was executed; no real-model exploit is claimed."
    )
