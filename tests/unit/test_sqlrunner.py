"""
test_sqlrunner.py - unit tests for the annotated-SQL runner. No server needed.
"""

import textwrap

import pytest

from sqlrunner import ADMIN, ScriptError, as_text, collect, judge, parse, render_rows


def write(tmp_path, body, name="script.sql"):
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return path


# ---- parse() ---------------------------------------------------------------------------

def test_parse_reads_metadata_steps_and_directives(tmp_path):
    script = parse(write(tmp_path, """\
        -- @title Demo title
        -- @goal First goal
        -- @goal Second goal
        -- @phase setup
        CREATE DATABASE x;
        -- @phase demo
        -- @as alice_student
        -- @why Because.
        -- @expect error 1142 grades
        SELECT *
          FROM grades;
        -- an ordinary comment is ignored
        -- @reconnect
        -- @expect rows 2
        SELECT 1;
        -- @expect error 1045
        -- @login bob wrong
        -- @takeaway Lesson.
    """))
    assert script.title == "Demo title"
    assert script.goals == ["First goal", "Second goal"]
    assert script.takeaways == ["Lesson."]
    setup, select, reselect, login = script.steps
    assert (setup.kind, setup.account, setup.phase, setup.expect) == ("sql", ADMIN, "setup", "ok")
    assert select.text == "SELECT *\n  FROM grades;"
    assert (select.account, select.expect, select.why) == ("alice_student", "error 1142 grades", ["Because."])
    assert reselect.reconnect_first and reselect.expect == "rows 2" and reselect.why == []
    assert (login.kind, login.account, login.login_mode, login.expect) == ("login", "bob", "wrong", "error 1045")


def test_expectation_and_why_apply_to_the_next_step_only(tmp_path):
    script = parse(write(tmp_path, """\
        -- @title t
        -- @expect error 1
        -- @why w
        SELECT 1;
        SELECT 2;
    """))
    assert [(step.expect, step.why) for step in script.steps] == [("error 1", ["w"]), ("ok", [])]


@pytest.mark.parametrize("body, message", [
    ("SELECT 1;\n", "missing '-- @title'"),
    ("-- @title t\n-- @frobnicate x\nSELECT 1;\n", "unknown directive @frobnicate"),
    ("-- @title t\nSELECT 1\n", "missing its closing ';'"),
    ("-- @title t\n-- @phase later\n", "unknown phase 'later'"),
    ("-- @title t\n-- @login bob sideways\n", "unknown login mode 'sideways'"),
])
def test_parse_rejects_malformed_files(tmp_path, body, message):
    with pytest.raises(ScriptError, match=message):
        parse(write(tmp_path, body))


def test_every_shipped_tutorial_file_parses():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    files = collect([root / "examples", root / "experiments"])
    assert len(files) >= 18
    for path in files:
        assert parse(path).steps, path.name


# ---- judge() ---------------------------------------------------------------------------

ROWS = [(1, "alpha"), (2, None)]


@pytest.mark.parametrize("expect, outcome, rows, verdict", [
    ("ok", "ok", [], True),
    ("ok", "error 1142: denied", [], False),
    ("any", "error 1142: denied", [], True),
    ("any", "ok", ROWS, True),
    ("rows 2", "ok", ROWS, True),
    ("rows 3", "ok", ROWS, False),
    ("rows 0", "error 1142: denied", [], False),
    ("contains alpha", "ok", ROWS, True),
    ("contains NULL", "ok", ROWS, True),
    ("contains beta", "ok", ROWS, False),
    ("contains alpha", "error 1: x", [], False),
    ("excludes beta", "ok", ROWS, True),
    ("excludes alpha", "ok", ROWS, False),
    ("excludes alpha", "error 1: x", [], False),
    ("error 1142", "error 1142: SELECT command denied for table `grades`", [], True),
    ("error 1142 grades", "error 1142: SELECT command denied for table `grades`", [], True),
    ("error 1142 students", "error 1142: SELECT command denied for table `grades`", [], False),
    ("error 1142", "error 11420: something else", [], False),
    ("error 1142", "ok", [], False),
])
def test_judge(expect, outcome, rows, verdict):
    assert judge(expect, outcome, rows) is verdict


def test_judge_rejects_unknown_expectations():
    with pytest.raises(ScriptError):
        judge("maybe", "ok", [])


# ---- helpers -----------------------------------------------------------------------------

def test_as_text_shows_sql_null():
    assert as_text((1, None, "x")) == "1 NULL x"


def test_render_rows_aligns_and_truncates():
    assert render_rows([]) == ["(no rows)"]
    assert render_rows([("a", "bb"), ("ccc", None)]) == ["a    bb", "ccc  NULL"]
    many = render_rows([(i,) for i in range(10)])
    assert many[-1] == "... 2 more rows" and len(many) == 9
