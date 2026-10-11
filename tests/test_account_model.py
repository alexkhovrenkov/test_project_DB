"""
test_account_model.py - "an authentication method instead of a password in a config file".

No account password exists in any file: root authenticates with unix_socket
(only via docker exec), the demo accounts start locked and get their passwords
from a person (make set-password) or from the harness (memory only), and the
harness itself needs a client certificate on top of its in-memory password.
"""

import json
import re
import secrets
import subprocess
import sys

import pymysql
import pytest

from admin import DOCKER, HARNESS_NAME, socket_sql
from conftest import error_code
from database import (ACCOUNTS, CONTAINER, PROJECT_DIR, connect, password_for, remember_password, run_query,
                      strong_password)

ACCESS_DENIED = 1045
ACCESS_DENIED_NO_PASSWORD = 1698   # what a failed unix_socket login returns
SKIPPED_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}


def project_files():
    for path in PROJECT_DIR.rglob("*"):
        if path.is_file() and not SKIPPED_DIRS.intersection(path.relative_to(PROJECT_DIR).parts):
            yield path


UNUSABLE_KEY = "Sv1MQTlVnCTyb4USqBdcQ87pFwhv7cbvwC5IIXBymhY"   # sql/04_users.sql, sql/06_lockdown.sh


def test_root_logs_in_through_the_container_socket_without_a_password():
    """docker exec ... mariadb as the OS user root: the unix_socket method of root's chain."""
    assert socket_sql("SELECT CURRENT_USER()") == ["root@localhost"]


def test_root_is_unix_socket_or_an_unusable_ed25519_key(dba):
    """root = unix_socket OR ed25519 USING '<key of a discarded secret>': no usable password exists."""
    (priv,) = run_query(dba, "SELECT Priv FROM mysql.global_priv WHERE User = 'root' AND Host = 'localhost'")[0]
    priv = json.loads(priv)
    assert priv["plugin"] == "ed25519" and priv["authentication_string"] == UNUSABLE_KEY
    assert [method.get("plugin") for method in priv["auth_or"]] == ["unix_socket", None]


def test_root_has_no_network_account(dba):
    assert run_query(dba, "SELECT host FROM mysql.user WHERE user = 'root'") == (("localhost",),)


@pytest.mark.parametrize("password", ["", "root", "anything-at-all"])
def test_root_cannot_log_in_over_the_network(password):
    assert error_code(lambda: connect("root", password, database=None)) == ACCESS_DENIED


def test_harness_account_is_refused_without_its_client_certificate(harness):
    """Right name, right password, verified TLS - but no client certificate: REQUIRE X509 says no."""
    assert HARNESS_NAME.match(harness.name)
    assert error_code(lambda: connect(harness.name, harness.password, database=None)) == ACCESS_DENIED
    harness.connect().close()   # control: with the certificate it works


def test_harness_account_requires_x509_and_holds_no_server_level_privileges(dba, harness):
    ssl_type = run_query(dba, "SELECT ssl_type FROM mysql.user WHERE user = %s", (harness.name,))[0][0]
    assert ssl_type == "X509"
    grants = " ".join(row[0] for row in run_query(dba, f"SHOW GRANTS FOR `{harness.name}`@'%'"))
    for dangerous in ("ALL PRIVILEGES", "SUPER", "FILE", "SHUTDOWN", "PROCESS", "CONNECTION ADMIN"):
        assert dangerous not in grants


def test_no_file_contains_an_account_password(harness):
    """Neither tracked nor generated files (.env, certs, ...) hold any password in use right now."""
    secrets_in_use = {harness.password} | {password_for(user) for user in ACCOUNTS.values()}
    for path in project_files():
        text = path.read_text(errors="ignore")
        for secret in secrets_in_use:
            assert secret not in text, f"a live password was found in {path.relative_to(PROJECT_DIR)}"


def test_env_files_hold_no_password_settings():
    """.env / .env.example may only carry non-secret settings (even commented-out ones)."""
    setting = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=")
    for name in (".env", ".env.example"):
        path = PROJECT_DIR / name
        if path.exists():
            keys = [m.group(1) for m in map(setting.match, path.read_text().splitlines()) if m]
            assert not [key for key in keys if "PASSWORD" in key], f"{name} defines a password"


def test_container_environment_and_data_directory_hold_no_password():
    inspect = subprocess.run([DOCKER, "inspect", CONTAINER, "--format", "{{json .Config.Env}}"],
                             capture_output=True, text=True, check=True)
    passwords = [entry for entry in json.loads(inspect.stdout) if "PASSWORD" in entry.split("=", 1)[0]]
    assert passwords == ["MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1"]
    # The image's healthcheck account and its password file were removed by sql/06_lockdown.sh.
    assert socket_sql("SELECT COUNT(*) FROM mysql.user WHERE user = 'healthcheck'") == ["0"]
    listing = subprocess.run([DOCKER, "exec", CONTAINER, "ls", "-a", "/var/lib/mysql"],
                             capture_output=True, text=True, check=True).stdout.split()
    assert ".my-healthcheck.cnf" not in listing


def test_init_scripts_create_demo_accounts_locked_and_without_a_password():
    users_sql = (PROJECT_DIR / "sql" / "04_users.sql").read_text()
    for user in ACCOUNTS.values():
        line = next(line for line in users_sql.splitlines() if line.startswith(f"CREATE USER '{user}'"))
        assert "ACCOUNT LOCK" in line and "PASSWORD(" not in line
    assert not list((PROJECT_DIR / "sql").glob("*.sh")) or all(
        "PASSWORD(" not in path.read_text() for path in (PROJECT_DIR / "sql").glob("*.sh"))


def test_plaintext_password_never_reaches_the_server_log(harness):
    """The harness password went through docker exec on stdin; it must not appear in the server log."""
    log = subprocess.run([DOCKER, "logs", CONTAINER], capture_output=True, text=True, check=True)
    assert harness.password not in log.stdout + log.stderr


def test_set_password_refuses_unknown_accounts():
    result = subprocess.run([sys.executable, "app/admin.py", "set-password", "root"],
                            cwd=PROJECT_DIR, capture_output=True, text=True)
    assert result.returncode != 0 and "Unknown account" in result.stderr


def test_demo_password_change_takes_effect(harness):
    """What make set-password does, as the harness: new password works, old one is refused."""
    old, new = password_for("jones_finance"), strong_password()
    run_query(harness.connection,
              "ALTER USER `jones_finance`@'%%' IDENTIFIED VIA ed25519 USING PASSWORD(%s)", (new,))
    remember_password("jones_finance", new)
    connect("jones_finance", new).close()
    assert error_code(lambda: connect("jones_finance", old)) == ACCESS_DENIED


def login_error_codes(user_names):
    codes = []
    for name in user_names:
        try:
            connect(name, "wrong-Password-1", database=None)
        except pymysql.MySQLError as error:
            codes.append(error.args[0])
    return codes


def test_unknown_users_are_indistinguishable_from_real_ones():
    """Finding 12, closed: 200 unknown names all fail exactly like a real account (1045)."""
    codes = login_error_codes(f"no_such_user_{secrets.token_hex(4)}" for _ in range(200))
    assert set(codes) == {1045}
    assert set(login_error_codes(["smith_professor"] * 20)) == {1045}


def test_a_unix_socket_only_account_opens_a_user_enumeration_oracle(dba):
    """Finding 12, the cause: for an unknown user MariaDB imitates the plugin of a random
    existing account. Add unix_socket-only accounts and unknown names start failing with 1698
    (real network accounts never do), which tells an attacker the name does not exist."""
    names = [f"t_sock_{secrets.token_hex(4)}" for _ in range(10)]
    try:
        for name in names:
            run_query(dba, f"CREATE USER {name}@localhost IDENTIFIED VIA unix_socket")
        codes = login_error_codes(f"no_such_user_{secrets.token_hex(4)}" for _ in range(60))
        assert ACCESS_DENIED_NO_PASSWORD in codes and ACCESS_DENIED in codes
        assert set(login_error_codes(["smith_professor"] * 20)) == {ACCESS_DENIED}
    finally:
        for name in names:
            run_query(dba, f"DROP USER IF EXISTS {name}@localhost")
