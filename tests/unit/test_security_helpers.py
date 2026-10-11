"""
test_security_helpers.py - unit tests (no server) for the code that handles
passwords and user input: socket_sql escaping, generated passwords, the
grade update validation and the demo's expectation table.
"""

import re
import subprocess

import pytest

import admin
from actions import update_grade
from database import ACCOUNTS, strong_password
from demo import ACTION_ORDER, POLICY


class FakeRun:
    """Captures what socket_sql would hand to `docker exec`."""

    def __init__(self):
        self.calls = []

    def __call__(self, command, input, **kwargs):
        self.calls.append((command, input))
        return subprocess.CompletedProcess(command, 0, stdout="ok\n", stderr="")


@pytest.fixture
def fake_run(monkeypatch):
    fake = FakeRun()
    monkeypatch.setattr(admin.subprocess, "run", fake)
    return fake


def test_socket_sql_escapes_values_like_the_driver_and_keeps_them_off_the_command_line(fake_run):
    hostile = "x'); DROP USER root@localhost; -- \\"
    admin.socket_sql("ALTER USER `u`@'%%' IDENTIFIED VIA ed25519 USING PASSWORD(%s)", (hostile,))
    command, stdin = fake_run.calls[0]
    assert hostile not in " ".join(command)                       # never on the command line
    assert stdin == ("ALTER USER `u`@'%' IDENTIFIED VIA ed25519 USING PASSWORD("
                     "'x\\'); DROP USER root@localhost; -- \\\\')")  # one quoted, escaped literal


def test_socket_sql_uses_socket_root_in_the_configured_container(fake_run):
    admin.socket_sql("SELECT 1")
    command, stdin = fake_run.calls[0]
    assert command[:4] == [admin.DOCKER, "exec", "-i", admin.CONTAINER]
    assert "--protocol=socket" in command and "--user=root" in command
    assert "--skip-print-query-on-error" in command   # never echo a statement (and its password) on error
    assert not [part for part in command if part.startswith(("-p", "--password"))]
    assert stdin == "SELECT 1"


def test_socket_sql_reports_errors(monkeypatch):
    monkeypatch.setattr(admin.subprocess, "run", lambda command, **kw: subprocess.CompletedProcess(
        command, 1, stdout="", stderr="ERROR 1045 (28000): Access denied"))
    with pytest.raises(admin.SocketSQLError, match="1045"):
        admin.socket_sql("SELECT 1")


def test_set_password_only_accepts_the_demo_accounts(monkeypatch):
    with pytest.raises(SystemExit, match="Unknown account"):
        admin.set_password("root")


def test_harness_names_are_generated_and_validated():
    names = {admin.Harness().name for _ in range(20)}
    assert len(names) == 20 and all(admin.HARNESS_NAME.match(name) for name in names)


@pytest.mark.parametrize("attempt", range(50))
def test_generated_passwords_meet_the_server_policy(attempt):
    """simple_password_check as configured: 12+ chars, upper, lower, digit, special; quote-free."""
    password = strong_password()
    assert len(password) >= 12
    for pattern in (r"[A-Z]", r"[a-z]", r"[0-9]", r"[^A-Za-z0-9]"):
        assert re.search(pattern, password)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", password)


@pytest.mark.parametrize("grade_id, grade", [("1; DROP TABLE grades", "1.3"), ("1 OR 1=1", "1.3"), ("1", "abc"),
                                             ("", "1.3"), ("1", "NaN"), ("1", "Infinity")])
def test_update_grade_validates_before_touching_the_database(grade_id, grade):
    with pytest.raises(ValueError):
        update_grade(None, grade_id, grade)   # no connection: must fail before any SQL is sent


def test_demo_policy_covers_every_role_and_action():
    for action in ACTION_ORDER:
        assert set(POLICY[action]) == set(ACCOUNTS)
