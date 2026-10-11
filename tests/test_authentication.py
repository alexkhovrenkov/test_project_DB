"""
test_authentication.py - attacks on ED25519 AUTHENTICATION, against the real server.

A failed login must be rejected before any query runs, with the exact error code.
"""

import secrets

import pymysql
import pytest

from conftest import error_code
from database import ACCOUNTS, connect, connect_as, password_from_env, run_query

ACCESS_DENIED = 1045      # "Access denied for user ..." - the login itself failed
ACCOUNT_LOCKED = 4151
PASSWORD_EXPIRED = 1820


def test_every_password_account_uses_ed25519(root):
    names = [user for user, _ in ACCOUNTS.values()] + ["root"]
    rows = run_query(root, "SELECT user, host, plugin FROM mysql.user WHERE user IN %s", (names,))
    assert len(rows) == len(names) + 1, "expected the 4 demo users plus root@localhost and root@%"
    assert {plugin for _, _, plugin in rows} == {"ed25519"}


@pytest.mark.parametrize("role", list(ACCOUNTS))
def test_correct_password_logs_in_as_the_expected_user(role):
    connection = connect_as(role)
    try:
        user = run_query(connection, "SELECT CURRENT_USER()")[0][0]
        assert user == f"{ACCOUNTS[role][0]}@%"
        assert run_query(connection, "SELECT CURRENT_ROLE()")[0][0] == f"{role}_role"
    finally:
        connection.close()


@pytest.mark.parametrize("role", list(ACCOUNTS))
def test_wrong_password_is_rejected(role):
    assert error_code(lambda: connect(ACCOUNTS[role][0], "definitely-not-the-password")) == ACCESS_DENIED


def test_empty_password_is_rejected():
    assert error_code(lambda: connect("smith_professor", "")) == ACCESS_DENIED


def test_password_of_another_user_is_rejected():
    assert error_code(lambda: connect("smith_professor", password_from_env("STUDENT_PASSWORD"))) == ACCESS_DENIED


def test_unknown_user_and_wrong_password_look_identical():
    """No user enumeration: same error code, same message shape."""
    def failure(user):
        try:
            connect(user, "wrong-password")
        except pymysql.MySQLError as error:
            return error.args[0], error.args[1].replace(user, "<user>")
    assert failure("smith_professor") == failure("no_such_user_" + secrets.token_hex(3))


def test_stolen_authentication_string_cannot_be_used_as_a_password(root):
    """ED25519 stores a PUBLIC key; knowing it is not enough to log in."""
    stored = run_query(root, "SELECT authentication_string FROM mysql.user WHERE user = 'smith_professor'")[0][0]
    assert stored and stored != password_from_env("PROFESSOR_PASSWORD")
    assert error_code(lambda: connect("smith_professor", stored)) == ACCESS_DENIED


def test_password_is_not_stored_anywhere_in_clear_text(root):
    password = password_from_env("PROFESSOR_PASSWORD")
    for (stored,) in run_query(root, "SELECT authentication_string FROM mysql.user"):
        assert password not in (stored or "")
    for (priv,) in run_query(root, "SELECT Priv FROM mysql.global_priv"):
        assert password not in priv


def test_locked_account_rejects_the_correct_password(lab):
    account = lab.account("locked")
    lab.run(f"ALTER USER {account[0]}@'%' ACCOUNT LOCK")
    assert error_code(lambda: connect(*account, database=None)) == ACCOUNT_LOCKED
    lab.run(f"ALTER USER {account[0]}@'%' ACCOUNT UNLOCK")
    connect(*account, database=None).close()


def test_expired_password_blocks_every_statement(lab):
    account = lab.account("expired")
    lab.run(f"ALTER USER {account[0]}@'%' PASSWORD EXPIRE")
    with lab.session(account) as session:
        assert error_code(lambda: run_query(session, "SELECT 1")) == PASSWORD_EXPIRED


def test_ed25519_account_can_be_created_and_used(lab):
    account = lab.account("fresh")
    plugin = lab.run("SELECT plugin FROM mysql.user WHERE user = %s", (account[0],))[0][0]
    assert plugin == "ed25519"
    with lab.session(account) as session:
        assert run_query(session, "SELECT 1") == ((1,),)
