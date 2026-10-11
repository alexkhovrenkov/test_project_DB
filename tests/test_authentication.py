"""
test_authentication.py - attacks on ED25519 AUTHENTICATION.

Run:  python tests/test_authentication.py
"""

import os
import sys

from checks import expect_allowed, expect_blocked, summary
from database import connect, run_query

ACCESS_DENIED = 1045   # "Access denied for user ..." - the login itself failed

PROFESSOR_PASSWORD = os.environ["PROFESSOR_PASSWORD"]


def run():
    print("\n--- Authentication (ED25519) ---")
    root = connect("root", os.environ["MARIADB_ROOT_PASSWORD"])

    def all_accounts_use_ed25519():
        rows = run_query(root, "SELECT user, plugin FROM mysql.user WHERE user IN "
                               "('alice_student', 'smith_professor', 'jones_finance', 'uni_admin', 'root')")
        assert len(rows) == 6, f"expected 4 demo users + 2 root accounts, found {len(rows)}"
        for user, plugin in rows:
            assert plugin == "ed25519", f"{user} uses {plugin}"
    expect_allowed("All demo accounts and root use the ed25519 plugin", all_accounts_use_ed25519)

    def correct_password_logs_in():
        connection = connect("smith_professor", PROFESSOR_PASSWORD)
        user = run_query(connection, "SELECT CURRENT_USER()")[0][0]
        assert user == "smith_professor@%", user
    expect_allowed("Correct password: login succeeds", correct_password_logs_in)

    expect_blocked("Wrong password: login rejected",
                   lambda: connect("smith_professor", "wrong-password"),
                   ACCESS_DENIED)

    expect_blocked("Unknown user: login rejected (same error, does not reveal the user is missing)",
                   lambda: connect("hacker", "anything"),
                   ACCESS_DENIED)

    # Attack: an attacker somehow read the mysql.user table (e.g. from a stolen
    # backup) and tries to log in with the stored value. ED25519 stores a
    # PUBLIC key, which cannot be used as the password.
    stolen_value = run_query(root, "SELECT authentication_string FROM mysql.user "
                                   "WHERE user = 'smith_professor'")[0][0]
    expect_blocked("Stolen authentication_string used as password: login rejected",
                   lambda: connect("smith_professor", stolen_value),
                   ACCESS_DENIED)


if __name__ == "__main__":
    run()
    sys.exit(summary())
