"""
demo.py - connect as one university role and try the same actions as every
other role. MariaDB decides what succeeds; this script only reports it.

Usage:
    python app/demo.py student
    python app/demo.py professor
    python app/demo.py finance
    python app/demo.py admin
    python app/demo.py            (runs all four, one after another)
"""

import sys

import pymysql

from database import ACCOUNTS, connect_as, run_query

# Every role tries exactly these actions. (description, SQL, parameters)
ACTIONS = [
    ("Read the course list",
     "SELECT code, title FROM courses", None),
    ("Read my own grades (view)",
     "SELECT code, title, grade FROM my_grades", None),
    ("Read student contact details",
     "SELECT first_name, last_name, email FROM students", None),
    ("Read ALL grades",
     "SELECT student_id, course_id, grade FROM grades", None),
    # Sets grade 1 to the value it already has, so running the demo never
    # changes the data. %s placeholders = parameterized query.
    ("Change a grade",
     "UPDATE grades SET grade = %s WHERE grade_id = %s", (1.3, 1)),
    ("Read financial records (IBANs)",
     "SELECT student_id, amount_paid, bank_iban FROM financial_records", None),
]


def show_session(connection):
    """Print who we are logged in as, the active role, and the TLS details."""
    user, role = run_query(connection, "SELECT CURRENT_USER(), CURRENT_ROLE()")[0]
    tls = dict(run_query(connection, "SHOW SESSION STATUS WHERE Variable_name IN ('Ssl_version', 'Ssl_cipher')"))
    print(f"Logged in as : {user}   (active role: {role})")
    print(f"TLS          : {tls['Ssl_version']}  {tls['Ssl_cipher']}  (certificate verified)")


def run_demo(role):
    print()
    print("=" * 70)
    print(f" ROLE: {role}")
    print("=" * 70)
    connection = connect_as(role)
    show_session(connection)
    print()

    for description, sql, params in ACTIONS:
        try:
            rows = run_query(connection, sql, params)
            if sql.startswith("SELECT"):
                print(f"  ALLOWED  {description}  ({len(rows)} rows returned)")
            else:
                print(f"  ALLOWED  {description}")
        except pymysql.MySQLError as error:
            # error.args = (MariaDB error code, message)
            code, message = error.args
            print(f"  DENIED   {description}")
            print(f"           MariaDB error {code}: {message}")

    connection.close()


def main():
    if len(sys.argv) == 1:
        roles = list(ACCOUNTS)
    elif sys.argv[1] in ACCOUNTS:
        roles = [sys.argv[1]]
    else:
        print(__doc__)
        sys.exit(1)

    for role in roles:
        run_demo(role)


if __name__ == "__main__":
    main()
