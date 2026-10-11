"""
test_tools.py - the user-facing programs, driven end to end against the real server:
the role demo, the SQL runner's command line, the interactive menu (with typed
input and getpass answered by the test), and make set-password.
"""

import builtins
import secrets
from types import SimpleNamespace

import pytest

import admin
import database
import demo
import menu
import sqlrunner
from database import ACCOUNTS, connect, password_for, remember_password, strong_password

PROJECT = database.PROJECT_DIR


@pytest.fixture
def typed(monkeypatch):
    """Feed answers to input() and getpass(), as if a person typed them in a terminal."""
    answers = []
    monkeypatch.setattr(builtins, "input", lambda prompt="": answers.pop(0))
    for module in (database, admin):
        monkeypatch.setattr(module.getpass, "getpass", lambda prompt="": answers.pop(0))
    monkeypatch.setattr(database, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)))
    return answers


@pytest.mark.parametrize("role", list(ACCOUNTS))
def test_role_demo_behaves_as_documented(role, capsys):
    assert demo.run_demo(role) == 0
    out = capsys.readouterr().out
    assert out.count("Result   : PASS") == 6 and "FAIL" not in out
    assert "certificate verified" in out


def test_role_demo_command_line_creates_its_own_harness(monkeypatch, capsys):
    monkeypatch.setattr(demo.sys, "argv", ["demo.py", "professor"])
    assert demo.main() == 0
    assert "Role demo: 6/6 actions behaved as expected." in capsys.readouterr().out


def test_role_demo_rejects_an_unknown_role(monkeypatch, capsys):
    monkeypatch.setattr(demo.sys, "argv", ["demo.py", "janitor"])
    assert demo.main() == 2


def test_sqlrunner_verbose_output_shows_every_part_of_a_step(harness):
    lines = []
    passed, failed = sqlrunner.run_script(PROJECT / "examples" / "02_deny.sql", harness, out=lines.append)
    text = "\n".join(lines)
    assert failed == 0 and passed > 10
    for part in ("Goal:", "[setup] PASS", "    SQL      ", "    Expected ", "    Actual   ", "    Result   PASS",
                 "    Why      ", "[cleanup] PASS", "-> 02_deny.sql"):
        assert part in text, part


def test_sqlrunner_command_line(capsys):
    assert sqlrunner.main(["--quiet", str(PROJECT / "examples" / "03_role_inheritance.sql")]) == 0
    assert "TOTAL:" in capsys.readouterr().out


def test_sqlrunner_command_line_reports_a_broken_file(tmp_path, capsys):
    broken = tmp_path / "broken.sql"
    broken.write_text("SELECT 1;\n")
    assert sqlrunner.main([str(broken)]) == 2
    assert "missing '-- @title'" in capsys.readouterr().err


def test_menu_session(typed, capsys):
    """Wrong password, retry, allowed and refused actions, bad input, switching user, quitting."""
    professor_password, student_password = password_for("smith_professor"), password_for("alice_student")
    database.forget_password("smith_professor")
    database.forget_password("alice_student")
    typed.extend([
        "9",                                   # not a role -> asked again
        "2", "definitely-wrong",               # professor, wrong password -> login fails
        "2", professor_password,               # professor, right password
        "1",                                   # courses: allowed
        "6",                                   # financial records: DENY
        "5", "abc", "1.0",                     # change a grade with invalid input
        "5", "1", "1.3",                       # change grade 1 to its current value: allowed
        "8",                                   # unknown menu entry
        "7", "1", student_password,            # switch to the student
        "4",                                   # all grades: refused
        "0",                                   # quit
    ])
    menu.main()
    out = capsys.readouterr().out
    assert "Please type a number from 1 to 4." in out
    assert "Login failed (1045)" in out
    assert "CS201 | Databases" in out
    assert "MariaDB refused the request (error 1142)" in out and "financial_records" in out
    assert "Invalid input: grade id must be a whole number" in out
    assert "UPDATE accepted by MariaDB." in out
    assert "Unknown choice." in out
    assert "for table `university`.`grades`" in out
    assert out.rstrip().endswith("Bye!")
    assert typed == []


def test_password_for_refuses_to_guess_without_a_terminal():
    with pytest.raises(database.ConfigError, match="make set-password"):
        password_for("nobody_known_" + strong_password())


def test_set_password_sets_a_typed_password_and_unlocks_the_account(typed, capsys):
    new = strong_password()
    typed.extend([new, new])
    admin.set_password("uni_admin")
    assert "Password set and account unlocked" in capsys.readouterr().out
    remember_password("uni_admin", new)
    connect("uni_admin", new).close()


def test_set_password_refuses_mismatched_and_weak_passwords(typed):
    typed.extend(["One-Passw0rd-123", "Other-Passw0rd-456"])
    with pytest.raises(SystemExit, match="differ"):
        admin.set_password("uni_admin")
    # New on every run: even a REFUSED password enters the reuse history (finding 9).
    weak = "weak-no-capitals-" + secrets.token_hex(4)
    typed.extend([weak, weak])
    with pytest.raises(SystemExit, match="MariaDB refused.*1819.*simple_password_check") as refused:
        admin.set_password("uni_admin")
    assert weak not in str(refused.value)   # the typed password is never echoed back


def test_admin_command_line_rejects_unknown_accounts():
    with pytest.raises(SystemExit, match="Unknown account"):
        admin.main(["set-password", "root"])
