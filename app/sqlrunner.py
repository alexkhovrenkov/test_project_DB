"""
sqlrunner.py - runs annotated SQL tutorial files as different MariaDB users.

The files in examples/ and experiments/ are plain SQL with a few special
comment lines ("directives"). Every statement is really executed on the
server, over a verified TLS connection, as the user named by the last "@as"
line. The runner compares what MariaDB answered with what the file expected
and prints PASS or FAIL for every step.

Usage:
    python app/sqlrunner.py examples/01_roles_and_grants.sql
    python app/sqlrunner.py examples/ experiments/        (every .sql file inside)
    python app/sqlrunner.py --quiet experiments/          (only the PASS/FAIL lines)

Directives (all start with "-- @"):
    @title <text>            name of the experiment               (once per file)
    @goal <text>             what you learn / what is investigated (repeatable)
    @phase setup|demo|cleanup  setup and cleanup steps are printed in one line
                             each; "demo" steps get the full expected/actual box
    @as <account>            run the following statements as this MariaDB account:
                             "dba" (the run's short-lived administrator, see
                             app/admin.py), a demo account such as alice_student,
                             or a user the file creates
    @reconnect               close and reopen the current account's connection
                             (global privileges are read at connection time)
    @login <account> [wrong] try to log in; the step is the login itself.
                             "wrong" uses an incorrect password.
    @expect <what>           for the next step: "ok" (default), "error <code> [text]",
                             "rows <n>", "contains <text>", "excludes <text>" (ok, and
                             no returned row contains the text) or "any"
    @why <text>              explanation printed under the next step (repeatable)
    @takeaway <text>         security implication, printed at the end (repeatable)

Placeholders: '{{pw}}' in a statement stands for a random password generated
for each run, so example files never contain a credential. It is sent as a
driver parameter (%s), not pasted into the SQL text.
{{run}} is replaced by a random hex string (6 characters) that is the same for
the whole run; it is used in account names that must be new on every run.
It is generated here, never taken from input, so formatting it into an
identifier is safe.
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
import secrets
from pathlib import Path

import pymysql

from admin import Harness, SocketSQLError
from database import ACCOUNTS, ConfigError, connect, password_for, strong_password

DEMO_USERS = set(ACCOUNTS.values())
ADMIN = "dba"   # the alias the .sql files use for the run's harness account
MAX_ROWS_SHOWN = 8


@dataclass
class Step:
    kind: str                     # "sql" or "login"
    text: str                     # the SQL, or the login description
    account: str
    phase: str
    expect: str = "ok"
    why: list = field(default_factory=list)
    login_mode: str = ""          # "" or "wrong"
    reconnect_first: bool = False


@dataclass
class Script:
    path: Path
    title: str = ""
    goals: list = field(default_factory=list)
    takeaways: list = field(default_factory=list)
    steps: list = field(default_factory=list)


class ScriptError(ValueError):
    """The .sql file itself is malformed (a bug in the tutorial, not in MariaDB)."""


DIRECTIVE = re.compile(r"^--\s*@(\w+)\s*(.*)$")


def parse(path):
    """Turn a .sql file into a Script."""
    script = Script(Path(path))
    account, phase = ADMIN, "demo"
    expect, why, reconnect = "ok", [], False
    buffer = []

    for number, raw in enumerate(Path(path).read_text().splitlines(), start=1):
        line = raw.strip()
        match = DIRECTIVE.match(line)
        if match:
            name, value = match.group(1), match.group(2).strip()
            if name == "title":
                script.title = value
            elif name == "goal":
                script.goals.append(value)
            elif name == "takeaway":
                script.takeaways.append(value)
            elif name == "phase":
                if value not in ("setup", "demo", "cleanup"):
                    raise ScriptError(f"{path}:{number}: unknown phase {value!r}")
                phase = value
            elif name == "as":
                account = value
            elif name == "reconnect":
                reconnect = True
            elif name == "expect":
                expect = value
            elif name == "why":
                why.append(value)
            elif name == "login":
                parts = value.split()
                login_account = parts[0]
                mode = parts[1] if len(parts) > 1 else ""
                if mode not in ("", "wrong"):
                    raise ScriptError(f"{path}:{number}: unknown login mode {mode!r}")
                script.steps.append(Step("login", f"log in as {login_account}"
                                         + (" with a WRONG password" if mode else ""),
                                         login_account, phase, expect, why, mode))
                expect, why, reconnect = "ok", [], False
            else:
                raise ScriptError(f"{path}:{number}: unknown directive @{name}")
            continue
        if not line or line.startswith("--"):
            continue
        buffer.append(raw.rstrip())
        if line.endswith(";"):
            script.steps.append(Step("sql", "\n".join(buffer), account, phase,
                                     expect, why, reconnect_first=reconnect))
            buffer, expect, why, reconnect = [], "ok", [], False
    if buffer:
        raise ScriptError(f"{path}: last statement is missing its closing ';'")
    if not script.title:
        raise ScriptError(f"{path}: missing '-- @title'")
    return script


class Session:
    """Keeps one open connection per account for the duration of a script."""

    def __init__(self, harness, run_password):
        self.harness = harness
        self.run_password = run_password   # random, for accounts the script creates
        self.run_id = secrets.token_hex(3)  # for {{run}}
        self.connections = {}
        self.roles = {}

    def display(self, account):
        return f"{ADMIN} ({self.harness.name})" if account == ADMIN else account

    def password(self, account, wrong=False):
        if wrong:
            return "definitely-not-the-password"
        if account in DEMO_USERS:
            return password_for(account)
        return self.run_password

    def open(self, account, password):
        if account == ADMIN:
            return self.harness.connect()
        return connect(account, password, database=None)

    def account_name(self, account):
        return account.replace("{{run}}", self.run_id)

    def connection(self, account, fresh=False):
        account = self.account_name(account)
        if fresh:
            self.drop(account)
        if account not in self.connections:
            self.connections[account] = self.open(account, self.password(account))
            self.refresh_role(account)
        return self.connections[account]

    def drop(self, account):
        connection = self.connections.pop(account, None)
        if connection:
            connection.close()

    def refresh_role(self, account):
        with self.connections[account].cursor() as cursor:
            cursor.execute("SELECT CURRENT_ROLE()")
            self.roles[account] = cursor.fetchone()[0] or "none"

    def close(self):
        for account in list(self.connections):
            self.drop(account)


def describe_error(error):
    if len(error.args) >= 2:
        return error.args[0], str(error.args[1])
    return 0, str(error)


def render_rows(rows):
    if not rows:
        return ["(no rows)"]
    shown = [tuple("NULL" if value is None else str(value) for value in row) for row in rows[:MAX_ROWS_SHOWN]]
    widths = [max(len(row[i]) for row in shown) for i in range(len(shown[0]))]
    lines = ["  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip() for row in shown]
    if len(rows) > MAX_ROWS_SHOWN:
        lines.append(f"... {len(rows) - MAX_ROWS_SHOWN} more rows")
    return lines


def execute(step, session):
    """Run one step. Returns (outcome, rows) where outcome is 'ok' or 'error <code>: <message>'."""
    try:
        if step.kind == "login":
            account = session.account_name(step.account)
            password = session.password(account, wrong=bool(step.login_mode))
            session.open(account, password).close()
            return "ok", []
        connection = session.connection(step.account, fresh=step.reconnect_first)
        sql, params = step.text.replace("{{run}}", session.run_id), None
        if "'{{pw}}'" in sql:
            # The password becomes a driver parameter: %s, with any literal % doubled.
            sql, params = sql.replace("%", "%%").replace("'{{pw}}'", "%s"), (session.run_password,)
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            rows = list(cursor.fetchall()) if cursor.description else []
        if re.match(r"\s*SET\s+(DEFAULT\s+)?ROLE", sql, re.IGNORECASE):
            session.refresh_role(step.account)
        return "ok", rows
    except pymysql.MySQLError as error:
        code, message = describe_error(error)
        return f"error {code}: {message}", []


def as_text(row):
    """One result row as a single string (NULL for None), for contains/excludes checks."""
    return " ".join("NULL" if value is None else str(value) for value in row)


def judge(expect, outcome, rows):
    """Compare the expectation with what happened. Returns True if it matches."""
    kind, _, argument = expect.partition(" ")
    if kind == "any":
        return True
    if kind == "ok":
        return outcome == "ok"
    if kind == "rows":
        return outcome == "ok" and len(rows) == int(argument)
    if kind == "contains":
        return outcome == "ok" and any(argument in as_text(row) for row in rows)
    if kind == "excludes":
        return outcome == "ok" and not any(argument in as_text(row) for row in rows)
    if kind == "error":
        code, _, text = argument.partition(" ")
        return outcome.startswith(f"error {code}:") and text in outcome
    raise ScriptError(f"unknown expectation {expect!r}")


def summarize(outcome, rows):
    if outcome == "ok":
        return f"ok ({len(rows)} rows)" if rows else "ok"
    return outcome


def one_line(sql):
    return " ".join(sql.split())


def run_script(path, harness, quiet=False, out=print):
    """Run one file with the given admin.Harness. Returns (passed, failed) step counts."""
    script = parse(path)
    session = Session(harness, strong_password())
    passed = failed = 0
    if not quiet:
        out("")
        out("=" * 78)
        out(f" {script.title}")
        out(f" ({script.path.name})")
        out("=" * 78)
        for goal in script.goals:
            out(f"Goal: {goal}")
    number = 0
    cleaned = 0
    try:
        for step in script.steps:
            outcome, rows = execute(step, session)
            ok = judge(step.expect, outcome, rows)
            passed, failed = passed + ok, failed + (not ok)
            verdict = "PASS" if ok else "FAIL"
            if step.phase == "cleanup" and ok and not quiet:
                cleaned += 1   # reported as one summary line below
                continue
            if step.phase != "demo":
                if not quiet or not ok:
                    out(f"  [{step.phase}] {verdict} {one_line(step.text)}" + ("" if ok else f"\n           got: {outcome}"))
                continue
            number += 1
            if quiet:
                out(f"  [{verdict}] step {number} as {session.display(step.account)}: {one_line(step.text)[:90]}")
                if not ok:
                    out(f"         expected {step.expect!r}, got {summarize(outcome, rows)!r}")
                continue
            role = session.roles.get(step.account, "none")
            out("")
            out(f"Step {number}  user: {session.display(step.account)}  (active role: {role})")
            for sql_line in step.text.splitlines():
                out(f"    SQL      {sql_line.strip()}")
            out(f"    Expected {step.expect}")
            out(f"    Actual   {summarize(outcome, rows)}")
            for row_line in render_rows(rows) if rows else []:
                out(f"             | {row_line}")
            out(f"    Result   {verdict}")
            for sentence in step.why:
                out(f"    Why      {sentence}")
    finally:
        session.close()
    if not quiet:
        if cleaned:
            out(f"\n  [cleanup] PASS {cleaned} statements removed everything this script created")
        for takeaway in script.takeaways:
            out(f"Security implication: {takeaway}")
    out(f"-> {script.path.name}: {passed} passed, {failed} failed")
    return passed, failed


def collect(paths):
    files = []
    for entry in paths:
        entry = Path(entry)
        files.extend(sorted(entry.glob("*.sql")) if entry.is_dir() else [entry])
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="+", help=".sql files or directories")
    parser.add_argument("--quiet", action="store_true", help="print only PASS/FAIL lines")
    arguments = parser.parse_args(argv)

    total_passed = total_failed = 0
    try:
        with Harness() as harness:
            harness.activate_demo_accounts()
            for file in collect(arguments.paths):
                passed, failed = run_script(file, harness, quiet=arguments.quiet)
                total_passed, total_failed = total_passed + passed, total_failed + failed
    except (ConfigError, ScriptError, SocketSQLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except pymysql.MySQLError as error:
        print(f"ERROR: could not talk to MariaDB: {error}. Is the server up ('make up')?", file=sys.stderr)
        return 2
    print(f"\nTOTAL: {total_passed} steps passed, {total_failed} failed")
    return 1 if total_failed else 0


if __name__ == "__main__":
    sys.exit(main())
