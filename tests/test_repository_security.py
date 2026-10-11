"""
test_repository_security.py - hygiene checks for secrets and unsafe SQL in this repository.
"""

import re
import stat
import subprocess
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parent.parent


def tracked_files():
    output = subprocess.run(["git", "ls-files"], cwd=PROJECT, capture_output=True, text=True)
    if output.returncode != 0:
        pytest.skip("not a git checkout")
    return [PROJECT / name for name in output.stdout.splitlines() if (PROJECT / name).is_file()]


def test_private_keys_are_owner_readable_only():
    keys = sorted((PROJECT / "certs").glob("*-key.pem"))
    assert keys, "run 'make certs' first"
    for key in keys:
        mode = stat.S_IMODE(key.stat().st_mode)
        assert mode & 0o077 == 0, f"{key.name} is accessible by group/others (mode {oct(mode)})"


def test_no_secrets_or_keys_are_tracked_by_git():
    names = [path.name for path in tracked_files()]
    assert ".env" not in names
    assert not [name for name in names if name.endswith((".pem", ".key"))]
    pem_header = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")   # cannot match its own source line
    for path in tracked_files():
        assert not pem_header.search(path.read_text(errors="ignore")), f"private key material in {path.name}"


def test_env_file_is_ignored_and_not_a_placeholder():
    tracked_files()   # skips when this is not a git checkout
    ignored = subprocess.run(["git", "check-ignore", ".env", "certs/server-key.pem"], cwd=PROJECT,
                             capture_output=True, text=True)
    assert set(ignored.stdout.split()) == {".env", "certs/server-key.pem"}
    assert "change-me" not in (PROJECT / ".env").read_text(), "run 'make clean' and 'make env' for real passwords"


def test_no_hardcoded_passwords_in_tracked_code():
    suspicious = re.compile(r"""(password|passwd|pwd)\s*=\s*["'][^"'{%$\s][^"']{3,}["']""", re.IGNORECASE)
    allowed_files = {".env.example"}
    for path in tracked_files():
        if path.suffix not in {".py", ".sh", ".sql", ".yml", ".yaml"} or path.name in allowed_files:
            continue
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            match = suspicious.search(line)
            # "definitely-not-the-password" and the like are deliberately wrong test passwords.
            if match and "wrong" not in line.lower() and "not-the" not in line.lower() and "evil" not in line.lower():
                pytest.fail(f"{path.name}:{number}: possible hard-coded password: {line.strip()}")


def test_application_code_never_builds_sql_with_string_formatting():
    """app/ must pass values as parameters: no f-strings, .format() or % inside execute()/run_query() calls."""
    pattern = re.compile(r"(execute|run_query)\(\s*[^)]*?(f\"|f'|\.format\(|\"\s*%\s*[\(\w])")
    for path in (PROJECT / "app").glob("*.py"):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            assert not pattern.search(line), f"{path.name}:{number}: SQL built by string formatting: {line.strip()}"


def test_tls_verification_is_enabled_in_the_application():
    source = (PROJECT / "app" / "database.py").read_text()
    assert "ssl_verify_cert=True" in source and "ssl_verify_identity=True" in source
    assert "CERT_NONE" not in source and "ssl_disabled" not in source


def test_server_published_on_loopback_only():
    compose = (PROJECT / "docker-compose.yml").read_text()
    assert '"127.0.0.1:' in compose
