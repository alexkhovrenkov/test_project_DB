"""
test_permissions.py - attacks on ROLES, GRANT and DENY.

Run:  python tests/test_permissions.py
"""

import os
import sys

from checks import expect_allowed, expect_blocked, summary
from database import connect, connect_as, run_query

ACCESS_DENIED_TABLE = 1142    # "<command> command denied ... for table ..."
ACCESS_DENIED_COLUMN = 1143   # "<command> command denied ... for column ..."


def run():
    print("\n--- Roles, GRANT and DENY ---")
    professor = connect_as("professor")
    student = connect_as("student")
    finance = connect_as("finance")

    # The professor's broad GRANT SELECT ON university.* works...
    expect_allowed("Professor can read courses (GRANT)",
                   lambda: run_query(professor, "SELECT * FROM courses"))
    expect_allowed("Professor can read all grades (GRANT)",
                   lambda: run_query(professor, "SELECT * FROM grades"))

    # ...except where DENY says no.
    expect_blocked("Professor is blocked from financial_records (DENY)",
                   lambda: run_query(professor, "SELECT * FROM financial_records"),
                   ACCESS_DENIED_TABLE, "financial_records")

    # Column-level GRANT: grade yes, student_id no.
    expect_allowed("Professor can update the grade column",
                   lambda: run_query(professor, "UPDATE grades SET grade = %s WHERE grade_id = %s", (1.3, 1)))
    expect_blocked("Professor cannot move a grade to another student (column privilege)",
                   lambda: run_query(professor, "UPDATE grades SET student_id = %s WHERE grade_id = %s", (2, 1)),
                   ACCESS_DENIED_COLUMN, "student_id")

    # Student: no privilege on grades at all.
    expect_blocked("Student is blocked from changing a grade (no GRANT)",
                   lambda: run_query(student, "UPDATE grades SET grade = %s WHERE grade_id = %s", (1.0, 1)),
                   ACCESS_DENIED_TABLE, "grades")
    expect_blocked("Student is blocked from reading everyone's grades",
                   lambda: run_query(student, "SELECT * FROM grades"),
                   ACCESS_DENIED_TABLE, "grades")

    def student_sees_only_own_grades():
        rows = run_query(student, "SELECT * FROM my_grades")
        assert len(rows) == 2, f"expected Alice's 2 grades, got {len(rows)} rows"
    expect_allowed("Student sees only their own 2 grades through the my_grades view",
                   student_sees_only_own_grades)

    expect_blocked("Student is blocked from financial_records",
                   lambda: run_query(student, "SELECT * FROM financial_records"),
                   ACCESS_DENIED_TABLE, "financial_records")

    # Finance: money yes, grades no.
    expect_allowed("Finance can read financial_records",
                   lambda: run_query(finance, "SELECT * FROM financial_records"))
    expect_blocked("Finance is blocked from changing a grade",
                   lambda: run_query(finance, "UPDATE grades SET grade = %s WHERE grade_id = %s", (1.0, 1)),
                   ACCESS_DENIED_TABLE, "grades")

    # The interesting DENY case: an administrator later GRANTs the professor
    # role SELECT directly on financial_records. Does the DENY still win?
    root = connect("root", os.environ["MARIADB_ROOT_PASSWORD"])
    run_query(root, "GRANT SELECT ON university.financial_records TO professor_role")
    try:
        new_professor_session = connect_as("professor")
        expect_blocked("DENY still wins after an explicit table-level GRANT",
                       lambda: run_query(new_professor_session, "SELECT * FROM financial_records"),
                       ACCESS_DENIED_TABLE, "financial_records")
    finally:
        # Undo the experiment so the database stays as setup created it.
        run_query(root, "REVOKE SELECT ON university.financial_records FROM professor_role")


if __name__ == "__main__":
    run()
    sys.exit(summary())
