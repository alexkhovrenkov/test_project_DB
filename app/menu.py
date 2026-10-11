"""
menu.py - an interactive version of the demo.

Pick a role, then choose actions from a menu. Every action is sent to MariaDB
as SQL; MariaDB decides whether it is allowed. This file contains NO
permission checks - every menu option is shown to every role on purpose.

Usage:
    python app/menu.py
"""

import pymysql

from database import ACCOUNTS, connect_as, run_query

ROLES = list(ACCOUNTS)   # ["student", "professor", "finance", "admin"]

# Menu number -> (text shown in the menu, SQL to run)
READ_ACTIONS = {
    "1": ("View courses",               "SELECT code, title, credits, professor FROM courses"),
    "2": ("View my grades",             "SELECT code, title, grade FROM my_grades"),
    "3": ("View students",              "SELECT student_id, first_name, last_name, email FROM students"),
    "4": ("View all grades",            "SELECT grade_id, student_id, course_id, grade FROM grades"),
    "6": ("View financial records",     "SELECT student_id, tuition_due, amount_paid, bank_iban FROM financial_records"),
}


def print_rows(rows):
    """Print query results as simple lines."""
    if not rows:
        print("  (no rows)")
    for row in rows:
        print("  " + " | ".join(str(value) for value in row))


def choose_role():
    print("\nWho do you want to log in as?")
    for number, role in enumerate(ROLES, start=1):
        user, _ = ACCOUNTS[role]
        print(f"  {number}. {role:<10} (MariaDB user: {user})")
    while True:
        choice = input("Choose 1-4: ").strip()
        if choice in ("1", "2", "3", "4"):
            return ROLES[int(choice) - 1]
        print("Please type a number from 1 to 4.")


def change_grade(connection):
    """Ask for a grade id and a new grade, then try the UPDATE."""
    grade_id = input("  Grade id to change (1-7): ").strip()
    new_grade = input("  New grade (e.g. 1.7): ").strip()
    # The user's input goes in as PARAMETERS (%s), never pasted into the SQL
    # text. That is what prevents SQL injection.
    run_query(connection,
              "UPDATE grades SET grade = %s WHERE grade_id = %s",
              (new_grade, grade_id))
    print("  UPDATE accepted by MariaDB.")


def show_menu(role):
    print(f"\n--- Logged in as {role} ---")
    for number in ("1", "2", "3", "4"):
        print(f"  {number}. {READ_ACTIONS[number][0]}")
    print("  5. Change a grade")
    print(f"  6. {READ_ACTIONS['6'][0]}")
    print("  7. Switch user")
    print("  0. Quit")


def main():
    role = choose_role()
    connection = connect_as(role)

    while True:
        show_menu(role)
        choice = input("Choose an action: ").strip()

        if choice == "0":
            break
        if choice == "7":
            connection.close()
            role = choose_role()
            connection = connect_as(role)
            continue

        try:
            if choice in READ_ACTIONS:
                description, sql = READ_ACTIONS[choice]
                print(f"\n{description}:")
                print_rows(run_query(connection, sql))
            elif choice == "5":
                change_grade(connection)
            else:
                print("Unknown choice.")
        except pymysql.MySQLError as error:
            # This is MariaDB saying no - we only print what it answered.
            # Error 1142/1143 = no permission. Other codes = e.g. invalid data.
            code, message = error.args
            print(f"\n  MariaDB refused the request (error {code}): {message}")

    connection.close()
    print("Bye!")


if __name__ == "__main__":
    main()
