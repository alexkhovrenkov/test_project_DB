"""
actions.py - the university operations that demo.py and menu.py send to MariaDB.

All SQL here is a fixed string; values travel as query parameters. Nothing in
this file decides who may run what: MariaDB does.
"""

from decimal import Decimal, InvalidOperation

from database import run_query

# key -> (description, SQL, parameters)
READ_ACTIONS = {
    "courses":   ("Read the course list",
                  "SELECT code, title, credits, professor FROM courses"),
    "my_grades": ("Read my own grades (view)",
                  "SELECT code, title, grade FROM my_grades"),
    "students":  ("Read student contact details",
                  "SELECT student_id, first_name, last_name, email FROM students"),
    "grades":    ("Read ALL grades",
                  "SELECT grade_id, student_id, course_id, grade FROM grades"),
    "financial": ("Read financial records (IBANs)",
                  "SELECT student_id, tuition_due, amount_paid, bank_iban FROM financial_records"),
}

UPDATE_GRADE_SQL = "UPDATE grades SET grade = %s WHERE grade_id = %s"


def update_grade(connection, grade_id, new_grade):
    """Change one grade. Raises ValueError for input that is not a number.

    The values are validated and then sent as parameters. Validation is for
    friendly errors (MariaDB would silently read "1abc" as 1); the parameters
    are what prevents SQL injection.
    """
    try:
        grade_id = int(grade_id)
        new_grade = Decimal(str(new_grade))
    except (ValueError, InvalidOperation):
        raise ValueError("grade id must be a whole number and the grade a decimal number") from None
    if not new_grade.is_finite():
        raise ValueError("grade must be a finite number")
    return run_query(connection, UPDATE_GRADE_SQL, (new_grade, grade_id))
