"""Fail on Gitleaks findings in Git history or nonignored source, without raw secrets."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def scan(scanner):
    scanner = str(Path(scanner).resolve(strict=True))
    # Empty explicit config uses built-in rules, ignoring repository/env allowlists.
    with tempfile.TemporaryDirectory(prefix="ai-security-scan-") as directory:
        temporary = Path(directory)
        config = temporary / "default.toml"
        config.write_text('[extend]\nuseDefault = true\n')
        common = ["--config", str(config), "--redact=100", "--no-banner", "--ignore-gitleaks-allow",
                  "--gitleaks-ignore-path", str(temporary / "absent-ignore-file")]
        subprocess.run([scanner, "git", str(ROOT), "--log-opts=--all", *common], check=True, cwd=ROOT)
        source = temporary / "source"
        source.mkdir()
        names = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT,
        ).split(b"\0")
        for encoded in set(names) - {b""}:
            relative = Path(encoded.decode("utf-8"))
            original = ROOT / relative
            if original.is_symlink() or not original.resolve().is_relative_to(ROOT) or relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError("Secret scan rejects unsafe source paths.")
            if not original.exists():  # Locally deleted tracked files remain in history scan.
                continue
            if not original.is_file():
                raise RuntimeError("Secret scan requires regular source files.")
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        subprocess.run([scanner, "dir", str(source), *common], check=True, cwd=temporary)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python ci/scan_secrets.py /path/to/gitleaks")
    scan(sys.argv[1])
