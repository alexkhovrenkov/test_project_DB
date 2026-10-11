"""
test_password_policy.py - password validation plugins (simple_password_check,
password_reuse_check) on ED25519 accounts. Account names are random per test,
because the reuse history outlives DROP USER (experiment 12).
"""

import secrets

import pymysql
import pytest

from conftest import error_code
from database import run_query, strong_password

POLICY_VIOLATION = 1819
ALTER_USER_FAILED = 1396
STRICT_VALIDATION = 1290


@pytest.fixture
def account_name(dba):
    name = f"t_pw_{secrets.token_hex(4)}"
    yield name
    run_query(dba, f"DROP USER IF EXISTS {name}@'%'")


def create(dba, name, password):
    return run_query(dba, f"CREATE USER {name}@'%%' IDENTIFIED VIA ed25519 USING PASSWORD(%s)", (password,))


def message(callable_):
    try:
        callable_()
    except pymysql.MySQLError as error:
        return error.args[1]
    pytest.fail("statement succeeded but should have been refused")


def test_policy_is_installed_and_configured(dba):
    variables = dict(run_query(dba, "SHOW VARIABLES WHERE Variable_name IN ('simple_password_check_minimal_length', "
                                    "'password_reuse_check_interval', 'strict_password_validation')"))
    assert variables == {"simple_password_check_minimal_length": "12", "password_reuse_check_interval": "365",
                         "strict_password_validation": "ON"}
    plugins = dict(run_query(dba, "SELECT plugin_name, plugin_status FROM information_schema.plugins "
                                  "WHERE plugin_type = 'PASSWORD VALIDATION'"))
    assert plugins == {"simple_password_check": "ACTIVE", "password_reuse_check": "ACTIVE"}


@pytest.mark.parametrize("weak", ["abc", "password12345", "PASSWORD-12345", "Password-short"])
def test_weak_passwords_are_refused(dba, account_name, weak):
    assert error_code(lambda: create(dba, account_name, weak)) == POLICY_VIOLATION


def test_generated_passwords_satisfy_the_policy(dba, account_name):
    create(dba, account_name, strong_password())


def test_precomputed_public_key_is_refused_by_strict_validation(dba, account_name):
    assert error_code(lambda: run_query(
        dba, f"CREATE USER {account_name}@'%' IDENTIFIED VIA ed25519 "
             "USING 'lEiAPNNMP1kq0dRsguIBKo/em5EPb9Y0272TblVhRUw'")) == STRICT_VALIDATION


def test_reuse_is_refused_by_set_password_with_1819(dba, account_name):
    password = strong_password()
    create(dba, account_name, password)
    text = message(lambda: run_query(dba, f"SET PASSWORD FOR {account_name}@'%%' = PASSWORD(%s)", (password,)))
    assert "password_reuse_check" in text
    assert run_query(dba, "SELECT plugin FROM mysql.user WHERE user = %s", (account_name,))[0][0] == "ed25519"


def test_reuse_through_alter_user_is_reported_as_1396(dba, account_name):
    """Finding: same policy violation, different error code; the reason is only in the warnings."""
    password = strong_password()
    create(dba, account_name, password)
    assert error_code(lambda: run_query(
        dba, f"ALTER USER {account_name}@'%%' IDENTIFIED VIA ed25519 USING PASSWORD(%s)", (password,))) \
        == ALTER_USER_FAILED
    warnings = " ".join(str(row) for row in run_query(dba, "SHOW WARNINGS"))
    assert "password_reuse_check: The password was already used" in warnings


def test_a_refused_password_is_still_recorded_as_used(dba, account_name):
    """Finding: the first attempt fails the strength check, the second fails as REUSED."""
    assert "simple_password_check" in message(lambda: create(dba, account_name, "abc"))
    assert "password_reuse_check" in message(lambda: create(dba, account_name, "abc"))


def test_reuse_history_survives_drop_user(dba, account_name):
    password = strong_password()
    create(dba, account_name, password)
    run_query(dba, f"DROP USER {account_name}@'%'")
    assert "password_reuse_check" in message(lambda: create(dba, account_name, password))


def test_two_accounts_may_share_a_password(dba, account_name):
    """Finding: reuse is checked per account only."""
    password, other = strong_password(), f"t_pw_{secrets.token_hex(4)}"
    create(dba, account_name, password)
    try:
        create(dba, other, password)
    finally:
        run_query(dba, f"DROP USER IF EXISTS {other}@'%'")


def test_password_containing_the_account_name_is_accepted(dba, account_name):
    create(dba, account_name, f"{account_name}-Password-1")
