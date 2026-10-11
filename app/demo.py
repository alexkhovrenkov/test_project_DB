"""
demo.py - connect as each university role and try the same six actions.

MariaDB decides what succeeds. For every action this script prints what we
EXPECT (from the permission design in sql/03_roles.sql), what MariaDB actually
answered, and PASS or FAIL. The expectations below are only a checklist used
for verification; nothing here enforces permissions.

Usage:
    python app/demo.py student
    python app/demo.py professor
    python app/demo.py finance
    python app/demo.py admin
    python app/demo.py            (runs all four, one after another)

Exit code 0 means every action behaved as expected. The demo accounts get fresh
random passwords for the run (kept in memory only): after the demo, use
"make set-password USER=..." to log in by hand.
"""

import sys

import pymysql

from actions import READ_ACTIONS, UPDATE_GRADE_SQL, update_grade
from admin import Harness, SocketSQLError
from database import ACCOUNTS, ConfigError, connect_as, run_query

ALLOW = "allowed"
DENY = "denied (error 1142)"

# The six actions every role tries, in order. The last one is a write that
# sets grade 1 to the value it already has, so running the demo never changes data.
ACTION_ORDER = ["courses", "my_grades", "students", "grades", "change_grade", "financial"]

DESCRIPTIONS = {key: READ_ACTIONS[key][0] for key in READ_ACTIONS}
DESCRIPTIONS["change_grade"] = "Change a grade"

# POLICY[action][role] = (expected outcome, why MariaDB decides this way)
POLICY = {
    "courses": {
        "student":   (ALLOW, "GRANT SELECT ON courses TO student_role"),
        "professor": (ALLOW, "GRANT SELECT ON university.* TO professor_role"),
        "finance":   (DENY,  "finance_role has no privilege on courses"),
        "admin":     (ALLOW, "GRANT ALL ON university.* TO admin_role"),
    },
    "my_grades": {
        "student":   (ALLOW, "GRANT SELECT ON my_grades; the view filters by USER()"),
        "professor": (ALLOW, "readable via university.*; 0 rows: the professor is not a student"),
        "finance":   (DENY,  "finance_role has no privilege on my_grades"),
        "admin":     (ALLOW, "ALL PRIVILEGES; 0 rows: the admin is not a student"),
    },
    "students": {
        "student":   (DENY,  "student_role has no privilege on students"),
        "professor": (ALLOW, "GRANT SELECT ON university.* TO professor_role"),
        "finance":   (ALLOW, "GRANT SELECT ON students TO finance_role"),
        "admin":     (ALLOW, "ALL PRIVILEGES"),
    },
    "grades": {
        "student":   (DENY,  "no privilege on grades (students use the my_grades view)"),
        "professor": (ALLOW, "GRANT SELECT ON university.* TO professor_role"),
        "finance":   (DENY,  "finance_role has no privilege on grades"),
        "admin":     (ALLOW, "ALL PRIVILEGES"),
    },
    "change_grade": {
        "student":   (DENY,  "no UPDATE privilege on grades"),
        "professor": (ALLOW, "GRANT UPDATE (grade) ON grades: column-level privilege"),
        "finance":   (DENY,  "no UPDATE privilege on grades"),
        "admin":     (ALLOW, "ALL PRIVILEGES"),
    },
    "financial": {
        "student":   (DENY,  "no privilege on financial_records"),
        "professor": (DENY,  "DENY SELECT ON financial_records TO professor_role beats the broad GRANT"),
        "finance":   (ALLOW, "GRANT SELECT, INSERT, UPDATE ON financial_records"),
        "admin":     (ALLOW, "ALL PRIVILEGES"),
    },
}


def perform(connection, action):
    """Send one action to MariaDB. Returns (SQL text, rows)."""
    if action == "change_grade":
        update_grade(connection, 1, "1.3")
        return UPDATE_GRADE_SQL, []
    sql = READ_ACTIONS[action][1]
    return sql, run_query(connection, sql)


def show_session(connection):
    """Print who we are logged in as, the active role, and the TLS details."""
    user, role = run_query(connection, "SELECT CURRENT_USER(), CURRENT_ROLE()")[0]
    tls = dict(run_query(connection, "SHOW SESSION STATUS WHERE Variable_name IN ('Ssl_version', 'Ssl_cipher')"))
    print(f"Logged in as : {user}   (active role: {role})")
    print(f"TLS          : {tls['Ssl_version']}  {tls['Ssl_cipher']}  "
          "(server certificate verified against certs/ca.pem)")


def run_demo(role):
    """Run the six actions as one role. Returns the number of FAILed actions."""
    account = ACCOUNTS[role]
    print()
    print("=" * 78)
    print(f" ROLE: {role}   (MariaDB account: {account})")
    print("=" * 78)
    connection = connect_as(role)
    show_session(connection)

    failures = 0
    for number, action in enumerate(ACTION_ORDER, start=1):
        expected, why = POLICY[action][role]
        try:
            sql, rows = perform(connection, action)
            actual = f"{ALLOW} ({len(rows)} rows)" if sql.startswith("SELECT") else ALLOW
            got_allowed = True
        except pymysql.MySQLError as error:
            code, message = error.args[0], error.args[1]
            sql = READ_ACTIONS[action][1] if action in READ_ACTIONS else UPDATE_GRADE_SQL
            actual = f"denied (error {code})"
            got_allowed = False
            denial_message = message
        passed = got_allowed == expected.startswith(ALLOW) and (got_allowed or "1142" in actual)
        failures += not passed

        print()
        print(f"[{number}/6] {DESCRIPTIONS[action]}")
        print(f"    User     : {account} (role {role}_role)")
        print(f"    SQL      : {sql}")
        print(f"    Expected : {expected}")
        print(f"    Actual   : {actual}")
        if not got_allowed:
            print(f"    MariaDB  : {denial_message}")
        print(f"    Result   : {'PASS' if passed else 'FAIL'}")
        print(f"    Why      : {why}")

    connection.close()
    return failures


def main():
    if len(sys.argv) == 1:
        roles = list(ACCOUNTS)
    elif sys.argv[1] in ACCOUNTS:
        roles = [sys.argv[1]]
    else:
        print(__doc__)
        return 2

    try:
        # A short-lived admin account gives the demo users fresh random passwords
        # that exist only in this process (see app/admin.py).
        with Harness() as harness:
            harness.activate_demo_accounts()
            failures = sum(run_demo(role) for role in roles)
    except (ConfigError, SocketSQLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except pymysql.MySQLError as error:
        print(f"ERROR: could not log in or talk to MariaDB: {error}", file=sys.stderr)
        return 2

    total = len(roles) * len(ACTION_ORDER)
    print(f"\nRole demo: {total - failures}/{total} actions behaved as expected.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
