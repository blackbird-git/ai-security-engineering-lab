"""Install one pinned official Linux x86-64 CI binary after SHA-256 verification."""

import argparse
import hashlib
import io
from pathlib import Path
import platform
import tarfile
import urllib.request

# Digests verified against each official release's checksums, 2026-11-04.
TOOLS = {
    "gitleaks": (
        "8.30.1",
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
    "actionlint": (
        "1.7.12",
        "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
        "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
    ),
}


def install(name, destination):
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise RuntimeError("CI binary requires Linux x86-64.")
    version, url, expected = TOOLS[name]
    with urllib.request.urlopen(url, timeout=60) as response:
        archive = response.read(32 * 1024 * 1024 + 1)
    if len(archive) > 32 * 1024 * 1024 or hashlib.sha256(archive).hexdigest() != expected:
        raise RuntimeError("CI binary checksum verification failed.")
    # Extract only the named regular executable; never extract arbitrary archive paths.
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        member = bundle.getmember(name)
        if not member.isfile() or not 0 < member.size <= 64 * 1024 * 1024:
            raise RuntimeError("Invalid CI binary archive.")
        binary = bundle.extractfile(member).read()
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / name
    target.write_bytes(binary)
    target.chmod(0o700)
    print(f"Installed {name} {version}; SHA-256 verified.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=TOOLS)
    parser.add_argument("destination")
    args = parser.parse_args()
    install(args.tool, args.destination)
