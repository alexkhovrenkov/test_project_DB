"""
test_deny_semantics.py - GRANT/DENY conflicts, role inheritance, column-level
privileges, REVOKE DENY and MariaDB-specific edge cases (MariaDB 13.1.2).

Each test builds its own throw-away database, roles and accounts (see the
`lab` fixture in conftest.py), so tests are independent and repeatable. The
same behaviours are also shown step by step in experiments/*.sql.
"""

import pytest

from conftest import ACCESS_DENIED_COLUMN, ACCESS_DENIED_TABLE, error_code
from database import connect_root, run_query

NO_SUCH_GRANT_DB, NO_SUCH_GRANT_TABLE = 1141, 1147
INVALID_ROLE = 1959


def read(session, db, table="t", columns="*"):
    return run_query(session, f"SELECT {columns} FROM {db}.{table}")


# ---- 1. GRANT and DENY conflicts -------------------------------------------------

def test_table_deny_beats_database_grant(lab):
    role = lab.role("r")
    user = lab.account("u", [role], role)
    lab.run(f"GRANT SELECT ON {lab.db}.* TO {role}")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {role}")
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db, "t")) == ACCESS_DENIED_TABLE
        assert read(session, lab.db, "u")   # the other table is unaffected


@pytest.mark.parametrize("deny_first", [True, False])
def test_order_of_grant_and_deny_is_irrelevant(lab, deny_first):
    role = lab.role("r")
    user = lab.account("u", [role], role)
    grant, deny = f"GRANT SELECT ON {lab.db}.t TO {role}", f"DENY SELECT ON {lab.db}.t TO {role}"
    for statement in ([deny, grant] if deny_first else [grant, deny]):
        lab.run(statement)
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE


def test_database_deny_masks_table_grant(lab):
    role = lab.role("r")
    user = lab.account("u", [role], role)
    lab.run(f"GRANT SELECT ON {lab.db}.t TO {role}")
    lab.run(f"DENY SELECT ON {lab.db}.* TO {role}")
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE


def test_table_deny_masks_column_grant(lab):
    user = lab.account("u")
    lab.run(f"GRANT SELECT (pub) ON {lab.db}.t TO {user[0]}@'%'")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {user[0]}@'%'")
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db, columns="pub")) == ACCESS_DENIED_TABLE


def test_deny_removes_only_the_privilege_it_names(lab):
    user = lab.account("u")
    lab.run(f"GRANT SELECT, INSERT ON {lab.db}.u TO {user[0]}@'%'")
    lab.run(f"DENY INSERT ON {lab.db}.u TO {user[0]}@'%'")
    with lab.session(user) as session:
        assert read(session, lab.db, "u")
        assert error_code(lambda: run_query(
            session, f"INSERT INTO {lab.db}.u VALUES (2, 'x')")) == ACCESS_DENIED_TABLE


# ---- 2. Role inheritance ---------------------------------------------------------

def test_privileges_are_inherited_through_nested_roles(lab):
    top, middle, bottom = lab.role("top"), lab.role("mid"), lab.role("bottom")
    lab.run(f"GRANT SELECT ON {lab.db}.t TO {bottom}")
    lab.run(f"GRANT {bottom} TO {middle}")
    lab.run(f"GRANT {middle} TO {top}")
    user = lab.account("u", [top], top)
    with lab.session(user) as session:
        assert read(session, lab.db)


def test_role_must_be_active_and_granted(lab):
    role, other = lab.role("r"), lab.role("other")
    lab.run(f"GRANT SELECT ON {lab.db}.t TO {role}")
    user = lab.account("u", [role])                  # granted, but no default role
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE
        run_query(session, f"SET ROLE {role}")
        assert read(session, lab.db)
        assert error_code(lambda: run_query(session, f"SET ROLE {other}")) == INVALID_ROLE


def test_deny_in_a_nested_role_beats_grant_in_another_branch_after_flush(lab):
    """Documented behaviour of 13.1.2: a DENY on an INHERITED role is only enforced once the
    role graph is rebuilt. Before FLUSH PRIVILEGES the user is still allowed (fail-open).
    If this test starts failing at the first assertion, the server was fixed: update the README."""
    team, readers, guard = lab.role("team"), lab.role("readers"), lab.role("guard")
    lab.run(f"GRANT SELECT ON {lab.db}.* TO {readers}")
    lab.run(f"GRANT {readers} TO {team}")
    lab.run(f"GRANT {guard} TO {team}")
    user = lab.account("u", [team], team)
    lab.run(f"DENY SELECT ON {lab.db}.t TO {guard}")
    with lab.session(user) as session:
        assert read(session, lab.db), "DENY on an inherited role is now enforced immediately (server behaviour changed)"
    lab.run("FLUSH PRIVILEGES")
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE
        assert read(session, lab.db, "u")


def test_deny_on_the_active_role_is_enforced_immediately(lab):
    role = lab.role("r")
    lab.run(f"GRANT SELECT ON {lab.db}.* TO {role}")
    user = lab.account("u", [role], role)
    with lab.session(user) as session:
        assert read(session, lab.db)                 # session is already open ...
        lab.run(f"DENY SELECT ON {lab.db}.t TO {role}")
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE   # ... and sees the DENY


# ---- 3. Column-level privileges --------------------------------------------------

def test_column_grant_allows_only_the_named_columns(lab):
    user = lab.account("u")
    lab.run(f"GRANT SELECT (id, pub) ON {lab.db}.t TO {user[0]}@'%'")
    with lab.session(user) as session:
        assert read(session, lab.db, columns="id, pub")
        assert error_code(lambda: read(session, lab.db, columns="secret")) == ACCESS_DENIED_COLUMN
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE    # SELECT * needs every column


def test_column_deny_blocks_the_column_in_every_clause(lab):
    user = lab.account("u")
    lab.run(f"GRANT SELECT ON {lab.db}.t TO {user[0]}@'%'")
    lab.run(f"DENY SELECT (secret) ON {lab.db}.t TO {user[0]}@'%'")
    with lab.session(user) as session:
        assert read(session, lab.db, columns="id, pub")
        for sql in (f"SELECT * FROM {lab.db}.t",
                    f"SELECT secret FROM {lab.db}.t",
                    f"SELECT id FROM {lab.db}.t WHERE secret = 'secret-1'",
                    f"SELECT id FROM {lab.db}.t ORDER BY secret",
                    f"SELECT MAX(secret) FROM {lab.db}.t"):
            assert error_code(lambda sql=sql: run_query(session, sql)) == ACCESS_DENIED_COLUMN, sql


def test_column_deny_leaks_the_column_name_through_show_create_table(lab):
    """Documented limitation: SHOW CREATE TABLE still prints the denied column."""
    user = lab.account("u")
    lab.run(f"GRANT SELECT ON {lab.db}.t TO {user[0]}@'%'")
    lab.run(f"DENY SELECT (secret) ON {lab.db}.t TO {user[0]}@'%'")
    with lab.session(user) as session:
        definition = run_query(session, f"SHOW CREATE TABLE {lab.db}.t")[0][1]
        assert "`secret`" in definition
        columns = {row[0] for row in run_query(session, f"SHOW COLUMNS FROM {lab.db}.t")}
        assert columns == {"id", "pub"}


# ---- 4. REVOKE DENY ----------------------------------------------------------------

def test_revoke_deny_restores_access_in_the_open_session(lab):
    role = lab.role("r")
    lab.run(f"GRANT SELECT ON {lab.db}.t TO {role}")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {role}")
    user = lab.account("u", [role], role)
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE
        lab.run(f"REVOKE DENY SELECT ON {lab.db}.t FROM {role}")
        assert read(session, lab.db)


def test_revoke_deny_must_match_the_level_exactly(lab):
    role = lab.role("r")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {role}")
    assert error_code(lambda: lab.run(f"REVOKE DENY SELECT ON {lab.db}.* FROM {role}")) == NO_SUCH_GRANT_DB
    assert error_code(lambda: lab.run(f"REVOKE DENY SELECT (pub) ON {lab.db}.t FROM {role}")) == NO_SUCH_GRANT_TABLE
    assert error_code(lambda: lab.run(f"REVOKE DENY INSERT ON {lab.db}.t FROM {role}")) == NO_SUCH_GRANT_TABLE
    lab.run(f"REVOKE DENY SELECT ON {lab.db}.t FROM {role}")   # the exact level works


def test_plain_revoke_does_not_remove_a_deny(lab):
    role = lab.role("r")
    lab.run(f"GRANT SELECT ON {lab.db}.t TO {role}")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {role}")
    lab.run(f"REVOKE SELECT ON {lab.db}.t FROM {role}")
    lines = [row[0] for row in lab.run(f"SHOW GRANTS FOR {role}")]
    assert any(line.startswith("DENY SELECT") for line in lines)


def test_table_level_revoke_deny_leaves_column_denies(lab):
    role = lab.role("r")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {role}")
    lab.run(f"DENY SELECT (pub) ON {lab.db}.t TO {role}")
    lab.run(f"REVOKE DENY SELECT ON {lab.db}.t FROM {role}")
    lines = [row[0] for row in lab.run(f"SHOW GRANTS FOR {role}")]
    assert any("DENY SELECT (`pub`)" in line for line in lines)


def test_revoke_all_clears_denies(lab):
    role = lab.role("r")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {role}")
    lab.run(f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {role}")
    assert not any(row[0].startswith("DENY") for row in lab.run(f"SHOW GRANTS FOR {role}"))


# ---- 5. MariaDB-specific edge cases ----------------------------------------------

def test_deny_attached_to_a_role_can_be_shed_with_set_role_none(lab):
    role = lab.role("r")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {role}")
    user = lab.account("u", [role], role)
    lab.run(f"GRANT SELECT ON {lab.db}.* TO {user[0]}@'%'")      # privilege outside the role
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE
        run_query(session, "SET ROLE NONE")
        assert read(session, lab.db)                              # the role's DENY is gone
        lab.run(f"DENY SELECT ON {lab.db}.t TO {user[0]}@'%'")    # anchor it to the account instead
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE


def test_deny_on_a_definer_does_not_follow_definer_views(lab):
    definer, viewer = lab.account("definer"), lab.account("viewer")
    lab.run(f"GRANT SELECT ON {lab.db}.t TO {definer[0]}@'%'")
    lab.run(f"CREATE DEFINER = {definer[0]}@'%' SQL SECURITY DEFINER VIEW {lab.db}.v AS SELECT id, pub FROM {lab.db}.t")
    lab.run(f"GRANT SELECT ON {lab.db}.v TO {viewer[0]}@'%'")
    lab.run(f"DENY SELECT ON {lab.db}.t TO {viewer[0]}@'%'")
    with lab.session(viewer) as session:
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE
        assert read(session, lab.db, "v")                        # reachable through the DEFINER view
    lab.run(f"DENY SELECT ON {lab.db}.v TO {viewer[0]}@'%'")
    with lab.session(viewer) as session:
        assert error_code(lambda: read(session, lab.db, "v")) == ACCESS_DENIED_TABLE


def test_unescaped_underscore_in_a_grant_matches_other_databases(lab):
    """Database names in GRANT are patterns: "_" matches any single character."""
    sibling = lab.db.replace("_", "9", 1)            # e.g. t9lab_1a2b3c4d - matches the pattern t_lab_1a2b3c4d
    lab.run(f"CREATE DATABASE {sibling}")
    try:
        lab.run(f"CREATE TABLE {sibling}.t (id INT)")
        user = lab.account("u")
        lab.run(f"GRANT SELECT ON {lab.db}.* TO {user[0]}@'%'")           # underscores NOT escaped
        with lab.session(user) as session:
            assert read(session, sibling, columns="id") == ()             # allowed: the grant leaked
        lab.run(f"REVOKE SELECT ON {lab.db}.* FROM {user[0]}@'%'")
        escaped = lab.db.replace("_", "\\_")
        lab.run(f"GRANT SELECT ON `{escaped}`.* TO {user[0]}@'%'")        # underscores escaped
        with lab.session(user) as session:
            assert error_code(lambda: read(session, sibling, columns="id")) == ACCESS_DENIED_TABLE
            assert read(session, lab.db)
    finally:
        lab.run(f"DROP DATABASE IF EXISTS {sibling}")


def test_a_deny_pattern_is_ignored_when_an_exact_grant_exists(lab):
    user = lab.account("u")
    escaped = lab.db.replace("_", "\\_")
    lab.run(f"GRANT SELECT ON `{escaped}`.* TO {user[0]}@'%'")
    lab.run(f"DENY SELECT ON `{escaped[:-3]}%`.* TO {user[0]}@'%'")       # broader pattern
    with lab.session(user) as session:
        assert read(session, lab.db)                                      # the more specific entry wins
    lab.run(f"DENY SELECT ON `{escaped}`.* TO {user[0]}@'%'")             # exact name
    with lab.session(user) as session:
        assert error_code(lambda: read(session, lab.db)) == ACCESS_DENIED_TABLE


def test_a_database_deny_survives_drop_database(lab):
    role = lab.role("r")
    lab.run(f"DENY SELECT ON {lab.db}.* TO {role}")
    lab.run(f"DROP DATABASE {lab.db}")
    assert any(row[0].startswith("DENY SELECT") for row in lab.run(f"SHOW GRANTS FOR {role}"))


def test_public_deny_locks_out_root_until_revoked(lab, root):
    lab.public_deny(f"{lab.db}.*")
    fresh_root = connect_root(database=None)
    try:
        assert error_code(lambda: read(fresh_root, lab.db)) == ACCESS_DENIED_TABLE
    finally:
        fresh_root.close()
    lab.run(f"REVOKE DENY SELECT ON {lab.db}.* FROM PUBLIC")
    lab.public_denies.clear()
    again = connect_root(database=None)
    try:
        assert read(again, lab.db)
    finally:
        again.close()
