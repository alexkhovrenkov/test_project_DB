"""
test_permissions.py - the university roles, GRANT and DENY, tested against the real server.

Every blocked operation must fail with the exact MariaDB error code, so a test
cannot pass because of an unrelated error (a typo, a missing table, ...).
"""

import pytest

from actions import READ_ACTIONS, update_grade
from conftest import ACCESS_DENIED_COLUMN, ACCESS_DENIED_TABLE, error_code
from database import connect, connect_as, run_query
from demo import ACTION_ORDER, DENY, POLICY, perform

ROLES = ["student", "professor", "finance", "admin"]


@pytest.mark.parametrize("action", ACTION_ORDER)
@pytest.mark.parametrize("role", ROLES)
def test_role_matrix(role, action, request):
    """The complete 4 roles x 6 actions matrix: allowed actions succeed, the others fail with 1142."""
    connection = request.getfixturevalue(role)
    expected = POLICY[action][role][0]
    if expected == DENY:
        assert error_code(lambda: perform(connection, action)) == ACCESS_DENIED_TABLE
    else:
        perform(connection, action)


def test_student_sees_exactly_their_own_grades(student):
    rows = run_query(student, "SELECT code, grade FROM my_grades ORDER BY code")
    assert [(code, str(grade)) for code, grade in rows] == [("CS105", "2.0"), ("CS201", "1.3")]


def test_student_cannot_widen_the_view(student):
    rows = run_query(student, "SELECT * FROM my_grades WHERE 1 = 1 OR code = 'x'")
    assert len(rows) == 2


def test_professor_can_change_the_grade_column_only(professor):
    update_grade(professor, 1, "1.3")   # same value as the data: the test leaves no trace
    assert error_code(lambda: run_query(
        professor, "UPDATE grades SET student_id = %s WHERE grade_id = %s", (2, 1))) == ACCESS_DENIED_COLUMN


def test_professor_cannot_insert_or_delete_grades(professor):
    assert error_code(lambda: run_query(
        professor, "INSERT INTO grades VALUES (99, 1, 101, 1.0)")) == ACCESS_DENIED_TABLE
    assert error_code(lambda: run_query(professor, "DELETE FROM grades WHERE grade_id = 1")) == ACCESS_DENIED_TABLE


def test_deny_beats_a_later_table_level_grant(dba):
    """The project's headline DENY property: an administrator's later GRANT cannot undo it."""
    run_query(dba, "GRANT SELECT ON university.financial_records TO professor_role")
    try:
        fresh_professor = connect_as("professor")   # a brand-new login, after the GRANT
        try:
            assert error_code(lambda: run_query(fresh_professor, "SELECT * FROM financial_records")) \
                == ACCESS_DENIED_TABLE
        finally:
            fresh_professor.close()
    finally:
        run_query(dba, "REVOKE SELECT ON university.financial_records FROM professor_role")


def test_professor_join_cannot_reach_the_denied_table(professor):
    sql = ("SELECT s.last_name, f.bank_iban FROM students s "
           "JOIN financial_records f ON f.student_id = s.student_id")
    assert error_code(lambda: run_query(professor, sql)) == ACCESS_DENIED_TABLE


def test_denied_table_is_hidden_from_show_tables(professor, student):
    professor_tables = {row[0] for row in run_query(professor, "SHOW TABLES")}
    assert professor_tables == {"courses", "grades", "my_grades", "students"}
    assert {row[0] for row in run_query(student, "SHOW TABLES")} == {"courses", "my_grades"}


def test_deny_is_visible_to_the_administrator_but_not_to_the_denied_user(dba, professor):
    admin_lines = [row[0] for row in run_query(dba, "SHOW GRANTS FOR professor_role")]
    assert "DENY SELECT ON `university`.`financial_records` TO `professor_role`" in admin_lines
    own_lines = [row[0] for row in run_query(professor, "SHOW GRANTS")]
    assert not any(line.startswith("DENY") for line in own_lines)


def test_deny_is_stored_in_global_priv_as_json(dba):
    """README claim: denies live in the 'denies' key of mysql.global_priv, not in the old grant tables."""
    (priv,) = run_query(dba, "SELECT Priv FROM mysql.global_priv WHERE User = 'professor_role'")[0]
    assert '"denies"' in priv and "financial_records" in priv


def test_admin_is_not_a_superuser(admin):
    assert error_code(lambda: run_query(admin, "SELECT * FROM mysql.user")) == ACCESS_DENIED_TABLE
    assert error_code(lambda: run_query(admin, "CREATE USER evil@'%' IDENTIFIED BY 'x'")) == 1227


def test_read_actions_are_fixed_sql_text():
    """The queries sent by the app are constants: no user value can end up inside the SQL text."""
    for _, sql in READ_ACTIONS.values():
        assert "%" not in sql and "{" not in sql


@pytest.mark.parametrize("payload", ["1; DROP TABLE grades", "1 OR 1=1", "1.3' --", "abc", ""])
def test_update_grade_rejects_injection_payloads(professor, payload):
    with pytest.raises(ValueError):
        update_grade(professor, payload, "1.3")
    with pytest.raises(ValueError):
        update_grade(professor, 1, payload)


def test_parameters_are_data_not_sql(professor):
    """A classic injection string as a PARAMETER matches nothing and changes nothing."""
    rows = run_query(professor, "SELECT code FROM courses WHERE title = %s", ("x' OR '1'='1",))
    assert rows == ()


def test_my_grades_view_is_defined_by_a_locked_read_only_account(dba):
    """The view lends its DEFINER's rights to students, so the definer must be tiny and unable to log in."""
    definer = run_query(dba, "SELECT definer, security_type FROM information_schema.views "
                              "WHERE table_schema = 'university' AND table_name = 'my_grades'")[0]
    assert definer == ("my_grades_owner@localhost", "DEFINER")
    privileges = {(schema_table, privilege) for schema_table, privilege in run_query(
        dba, "SELECT table_name, privilege_type FROM information_schema.table_privileges "
              "WHERE grantee = \"'my_grades_owner'@'localhost'\"")}
    assert privileges == {(table, "SELECT") for table in ("grades", "students", "courses")}
    locked = run_query(dba, "SELECT JSON_EXTRACT(Priv, '$.account_locked') FROM mysql.global_priv "
                             "WHERE User = 'my_grades_owner'")[0][0]
    assert locked == "true"
    # Reachable from nowhere on the network either: the account only exists for host 'localhost'.
    assert error_code(lambda: connect("my_grades_owner", "")) == 1045
