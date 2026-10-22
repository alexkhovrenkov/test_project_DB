"""
lab.py - the logic behind the Interactive Lab (the web frontend in frontend/).

The lab runs SQL AS one of the four demo accounts, over the same verified-TLS,
ED25519 connections as the rest of the project (database.py), so every answer
the browser shows - rows or a refusal - comes from MariaDB's own privilege
checks. Nothing here decides who may do what.

Safety, in layers:
  * MariaDB itself: the statement runs as a least-privilege demo account
    (no FILE, no account management, nothing outside `university`), and the
    driver connection does not allow several statements in one call.
  * check_statement(): one statement, only SELECT / SHOW / WITH / DESCRIBE /
    EXPLAIN, or a single INSERT / UPDATE / DELETE. No DDL, GRANT, SET, CALL...
  * every statement runs inside a transaction that is ALWAYS rolled back, so
    a write shows MariaDB's decision without changing the data.
  * max_statement_time (server-side timeout) and a cap on returned rows.

Administration (stats about accounts, giving the demo accounts their in-memory
passwords) goes through the run's short-lived harness account (admin.py).
"""

import datetime
import json
import re
import secrets
import ssl
import statistics
import threading
import time
from decimal import Decimal

import pymysql

from actions import READ_ACTIONS, UPDATE_GRADE_SQL
from admin import Harness, SocketSQLError
from database import ACCOUNTS, HOST, PORT, TRUSTED_CA, ConfigError, connect_as, password_for, run_query
from demo import ACTION_ORDER, ALLOW, DESCRIPTIONS, POLICY, perform
from lab_examples import CATEGORIES, EXAMPLES

MAX_SQL_LENGTH = 5000
MAX_ROWS = 200
STATEMENT_TIMEOUT_SECONDS = 5

READ_KEYWORDS = {"SELECT", "SHOW", "WITH", "DESCRIBE", "DESC", "EXPLAIN"}
WRITE_KEYWORDS = {"INSERT", "UPDATE", "DELETE"}

# MariaDB error codes that mean "you may not" (as opposed to "this is wrong").
DENIAL_CODES = {
    1044: "access denied to the database",
    1045: "access denied (wrong user name or password)",
    1142: "the command is denied for this table",
    1143: "the command is denied for this column",
    1227: "a global privilege is missing",
    1370: "EXECUTE is denied for this routine",
    1698: "access denied (authentication plugin)",
    4151: "the account is locked",
}
ERROR_HINTS = {
    1064: "SQL syntax error",
    1146: "the table does not exist",
    1054: "unknown column",
    1969: f"stopped by the lab's {STATEMENT_TIMEOUT_SECONDS}-second limit (max_statement_time)",
}
# Connection-level failures: the server went away or cannot be reached.
CONNECTION_ERRORS = {2002, 2003, 2006, 2013, 2055}

LEADING_COMMENT = re.compile(r"\A\s*(?:--[^\n]*(?:\n|\Z)|#[^\n]*(?:\n|\Z)|/\*.*?\*/)", re.DOTALL)
FIRST_WORD = re.compile(r"[A-Za-z]+")


class LabError(Exception):
    """A request the lab refuses before it reaches MariaDB (HTTP 400)."""


class LabUnavailable(Exception):
    """MariaDB (or Docker) cannot be reached (HTTP 503)."""


def check_statement(sql):
    """Validate one playground statement. Returns (statement, kind) with kind "read" or "write".

    This is a usability and defence-in-depth check; the real limit is the demo
    account's privileges, enforced by MariaDB.
    """
    if not isinstance(sql, str) or not sql.strip():
        raise LabError("Type a SQL statement first.")
    if len(sql) > MAX_SQL_LENGTH:
        raise LabError(f"The statement is longer than {MAX_SQL_LENGTH} characters.")
    if "/*!" in sql or "/*M!" in sql:
        raise LabError("Executable comments (/*! ... */) are not allowed in the lab.")
    statement = sql.strip().rstrip(";").strip()
    if ";" in statement:
        raise LabError("Run one statement at a time (remove the ';' inside the text).")
    body = statement
    while True:
        match = LEADING_COMMENT.match(body)
        if not match:
            break
        body = body[match.end():]
    word = FIRST_WORD.match(body.lstrip())
    keyword = word.group(0).upper() if word else ""
    if keyword in READ_KEYWORDS:
        return statement, "read"
    if keyword in WRITE_KEYWORDS:
        return statement, "write"
    raise LabError(f"The lab runs SELECT, SHOW, WITH, DESCRIBE, EXPLAIN and single INSERT/UPDATE/DELETE "
                   f"statements only (got {keyword or 'nothing'}). Writes are always rolled back.")


def to_json_value(value):
    """Make a value from PyMySQL JSON-friendly without losing precision."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime.date, datetime.datetime, datetime.time)):
        return value.isoformat()
    if isinstance(value, datetime.timedelta):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return "0x" + bytes(value).hex()
    return str(value)


def auth_chain(plugin, auth_or):
    """The account's authentication methods in order, e.g. ["unix_socket", "ed25519"].

    mysql.global_priv keeps an OR chain in "auth_or"; its entries name their plugin,
    except the entry that is the account's main plugin (the "plugin" key), stored as {}.
    """
    if not auth_or:
        return [plugin] if plugin else []
    entries = json.loads(auth_or) if isinstance(auth_or, str) else auth_or
    return [entry.get("plugin") or plugin for entry in entries]


def describe_error(error):
    """{code, message, outcome, hint} for a MariaDB error."""
    code = error.args[0] if error.args else None
    message = error.args[1] if len(error.args) > 1 else str(error)
    outcome = "denied" if code in DENIAL_CODES else "error"
    return {"code": code, "message": message, "outcome": outcome,
            "hint": DENIAL_CODES.get(code) or ERROR_HINTS.get(code)}


def summarize(samples):
    """Summary statistics of a list of milliseconds."""
    ordered = sorted(samples)
    if not ordered:
        return {"runs": 0}
    p95_index = max(0, min(len(ordered) - 1, round(0.95 * len(ordered)) - 1))
    return {
        "runs": len(ordered),
        "median": round(statistics.median(ordered), 3),
        "mean": round(statistics.fmean(ordered), 3),
        "stdev": round(statistics.stdev(ordered), 3) if len(ordered) > 1 else 0.0,
        "min": round(ordered[0], 3),
        "max": round(ordered[-1], 3),
        "p95": round(ordered[p95_index], 3),
    }


def bounded_runs(value, default=30, low=5, high=200):
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool):
        raise LabError("runs must be a whole number.")
    return max(low, min(high, value))


def milliseconds(start):
    return (time.perf_counter() - start) * 1000


class Lab:
    """Runs playground statements and benchmark scenarios against MariaDB.

    harness: an entered admin.Harness. If None, the lab creates its own when it
    first needs the server (and again after the server was restarted).
    """

    def __init__(self, harness=None):
        self._harness = harness
        self._owns_harness = harness is None
        self._lock = threading.Lock()
        # A harness handed in by the caller (the test suite) has already activated the demo accounts.
        self._activated = harness is not None

    # --- lifecycle ---------------------------------------------------------------------------

    def _ensure_harness(self):
        """The harness, created on first use. Must be called with self._lock held."""
        if self._harness is None:
            try:
                harness = Harness()
                harness.__enter__()
            except (ConfigError, SocketSQLError) as error:
                raise LabUnavailable(f"Cannot reach MariaDB through 'docker exec': {error}. "
                                     "Start it with 'make up'.") from None
            except pymysql.MySQLError as error:
                raise LabUnavailable(f"MariaDB is not answering: {error}") from None
            self._harness, self._owns_harness, self._activated = harness, True, False
        if not self._activated:
            try:
                self._harness.activate_demo_accounts()
            except pymysql.MySQLError as error:
                self._drop_harness()
                raise LabUnavailable(f"Could not prepare the demo accounts: {error}") from None
            self._activated = True
        return self._harness

    def _drop_harness(self):
        """Forget a harness whose server went away (it is recreated on the next request)."""
        if self._harness is not None and self._owns_harness:
            try:
                self._harness.__exit__(None, None, None)
            except (SocketSQLError, ConfigError, pymysql.MySQLError, OSError):
                pass
            self._harness = None
        self._activated = False

    def close(self):
        with self._lock:
            self._drop_harness()

    def _admin_query(self, sql, params=None):
        """A statement on the harness connection (serialized; it is one shared connection)."""
        with self._lock:
            harness = self._ensure_harness()
            try:
                return run_query(harness.connection, sql, params)
            except pymysql.err.OperationalError as error:
                if error.args and error.args[0] in CONNECTION_ERRORS:
                    self._drop_harness()
                    raise LabUnavailable(f"Lost the connection to MariaDB ({error.args[0]}). "
                                         "Is the server running? Try again.") from None
                raise

    def _connect(self, role):
        """A verified-TLS ED25519 connection as the demo account of `role`."""
        if role not in ACCOUNTS:
            raise LabError(f"Unknown role {role!r}. Choose one of: {', '.join(ACCOUNTS)}.")
        with self._lock:
            self._ensure_harness()
        for attempt in (1, 2):
            try:
                return connect_as(role)
            except pymysql.err.OperationalError as error:
                code = error.args[0] if error.args else None
                if code in (1045, 4151) and attempt == 1:
                    # Another tool (make demo / make test) gave the accounts new passwords.
                    with self._lock:
                        self._activated = False
                        self._ensure_harness()
                    continue
                if code in CONNECTION_ERRORS:
                    with self._lock:
                        self._drop_harness()
                    raise LabUnavailable(f"Cannot connect to MariaDB on {HOST}:{PORT} ({code}). "
                                         "Start it with 'make up'.") from None
                raise
        raise AssertionError("unreachable")

    # --- read-only information -------------------------------------------------------------

    def health(self):
        try:
            version, comment = self._admin_query("SELECT VERSION(), @@version_comment")[0]
        except LabUnavailable as error:
            return {"database": "down", "error": str(error)}
        return {"database": "up", "server_version": version, "server_comment": comment,
                "host": HOST, "port": PORT}

    def examples(self):
        return {"categories": [{"id": key, "title": title} for key, title in CATEGORIES],
                "examples": EXAMPLES,
                "roles": [{"role": role, "account": account} for role, account in ACCOUNTS.items()],
                "limits": {"max_rows": MAX_ROWS, "timeout_seconds": STATEMENT_TIMEOUT_SECONDS}}

    def stats(self):
        tables = self._admin_query(
            "SELECT 'students', COUNT(*) FROM university.students UNION ALL "
            "SELECT 'courses', COUNT(*) FROM university.courses UNION ALL "
            "SELECT 'grades', COUNT(*) FROM university.grades UNION ALL "
            "SELECT 'financial_records', COUNT(*) FROM university.financial_records")
        accounts = self._admin_query(
            "SELECT User, Host, JSON_VALUE(Priv, '$.plugin'), JSON_VALUE(Priv, '$.account_locked'), "
            "JSON_VALUE(Priv, '$.is_role'), JSON_LENGTH(JSON_EXTRACT(Priv, '$.denies')), "
            "JSON_EXTRACT(Priv, '$.auth_or') "
            "FROM mysql.global_priv WHERE User NOT LIKE 'harness%%' ORDER BY User")
        variables = dict(self._admin_query(
            "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version', 'require_secure_transport', "
            "'tls_version', 'have_ssl', 'simple_password_check_minimal_length', 'password_reuse_check_interval')"))
        plugins = self._admin_query(
            "SELECT PLUGIN_NAME, PLUGIN_STATUS, PLUGIN_TYPE FROM information_schema.PLUGINS "
            "WHERE PLUGIN_TYPE IN ('AUTHENTICATION', 'PASSWORD VALIDATION') ORDER BY PLUGIN_TYPE, PLUGIN_NAME")
        connection = self._connect("student")
        try:
            session_tls = dict(run_query(connection, "SHOW SESSION STATUS WHERE Variable_name IN "
                                                     "('Ssl_version', 'Ssl_cipher')"))
        finally:
            connection.close()
        return {
            "server": variables,
            "tables": [{"name": name, "rows": count} for name, count in tables],
            "accounts": [{"user": user, "host": host, "plugin": plugin, "locked": locked == "1",
                          "is_role": is_role == "1", "denies": denies or 0,
                          "auth_chain": auth_chain(plugin, methods)}
                         for user, host, plugin, locked, is_role, denies, methods in accounts],
            "plugins": [{"name": name, "status": status, "type": kind} for name, status, kind in plugins],
            "session_tls": {"version": session_tls.get("Ssl_version"), "cipher": session_tls.get("Ssl_cipher"),
                            "verified": True, "ca": "certs/ca.pem"},
        }

    # --- the playground ------------------------------------------------------------------------

    def run(self, role, sql):
        """Run one playground statement as `role`. Always rolled back."""
        statement, kind = check_statement(sql)
        connection = self._connect(role)
        try:
            user, active_role = run_query(connection, "SELECT CURRENT_USER(), CURRENT_ROLE()")[0]
            run_query(connection, "SET SESSION max_statement_time = %s", (STATEMENT_TIMEOUT_SECONDS,))
            connection.begin()
            start = time.perf_counter()
            try:
                with connection.cursor() as cursor:
                    affected = cursor.execute(statement)
                    rows = cursor.fetchmany(MAX_ROWS + 1) if cursor.description else []
                    columns = [column[0] for column in cursor.description or []]
                elapsed = milliseconds(start)
            except pymysql.MySQLError as error:
                elapsed = milliseconds(start)
                if error.args and error.args[0] in CONNECTION_ERRORS:
                    raise LabUnavailable(f"The connection to MariaDB was lost ({error.args[0]}).") from None
                return {"ok": False, "role": role, "account": user, "active_role": active_role, "kind": kind,
                        "elapsed_ms": round(elapsed, 3), "error": describe_error(error),
                        "outcome": describe_error(error)["outcome"]}
            finally:
                try:
                    connection.rollback()
                except pymysql.MySQLError:
                    pass
        finally:
            connection.close()
        truncated = len(rows) > MAX_ROWS
        rows = rows[:MAX_ROWS]
        return {"ok": True, "role": role, "account": user, "active_role": active_role, "kind": kind,
                "outcome": "allowed", "elapsed_ms": round(elapsed, 3), "columns": columns,
                "rows": [[to_json_value(value) for value in row] for row in rows],
                "row_count": len(rows) if columns else affected, "affected_rows": None if columns else affected,
                "truncated": truncated, "rolled_back": kind == "write"}

    # --- benchmarks -----------------------------------------------------------------------------

    def benchmark(self, scenario, runs=None):
        if scenario not in SCENARIOS:
            raise LabError(f"Unknown scenario {scenario!r}. Choose one of: {', '.join(SCENARIOS)}.")
        method = getattr(self, "_bench_" + scenario.replace("-", "_"))
        result = method(bounded_runs(runs))
        environment = self.health()
        result.update({"scenario": scenario, "title": SCENARIOS[scenario]["title"],
                       "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                       "environment": {"server_version": environment.get("server_version"),
                                       "client": "app/lab.py (PyMySQL), timer: time.perf_counter",
                                       "host": f"{HOST}:{PORT} (Docker, published on 127.0.0.1)"}})
        return result

    def _bench_access_matrix(self, runs):
        """The role demo's 4 x 6 matrix: what MariaDB answers, against the documented policy."""
        cells, per_role = [], []
        for role in ACCOUNTS:
            connection = self._connect(role)
            allowed = denied = matches = 0
            try:
                for action in ACTION_ORDER:
                    expected, why = POLICY[action][role]
                    connection.begin()
                    start = time.perf_counter()
                    try:
                        _, rows = perform(connection, action)
                        outcome, code, count = "allowed", None, len(rows)
                    except pymysql.MySQLError as error:
                        outcome, code, count = "denied", error.args[0], None
                    finally:
                        elapsed = milliseconds(start)
                        connection.rollback()
                    allowed += outcome == "allowed"
                    denied += outcome == "denied"
                    match = ((outcome == "allowed") == expected.startswith(ALLOW)
                             and (outcome == "allowed" or code == 1142))
                    matches += match
                    sql = READ_ACTIONS[action][1] if action in READ_ACTIONS else UPDATE_GRADE_SQL
                    cells.append({"role": role, "action": action, "description": DESCRIPTIONS[action], "sql": sql,
                                  "expected": expected, "outcome": outcome, "error": code, "rows": count,
                                  "match": match, "why": why, "elapsed_ms": round(elapsed, 3)})
            finally:
                connection.close()
            per_role.append({"label": role, "allowed": allowed, "denied": denied, "matches": matches})
        total = len(cells)
        return {"kind": "matrix", "runs": 1, "comparison": per_role, "cells": cells,
                "headline": f"{sum(cell['match'] for cell in cells)}/{total} answers match the documented policy",
                "method": "Each role opens one verified-TLS ED25519 connection and performs the role demo's six "
                          "actions (app/demo.py) once, each in a transaction that is rolled back. 'Expected' is "
                          "the policy table of app/demo.py; 'actual' is MariaDB's answer."}

    def _bench_login_errors(self, runs):
        """Finding 12: does a login with an unknown user name fail differently from a wrong password?"""
        groups = {"unknown user name": [], "real account, wrong password": []}
        timings = {label: [] for label in groups}
        for _ in range(runs):
            for label, user in (("unknown user name", "nobody_" + secrets.token_hex(4)),
                                ("real account, wrong password", ACCOUNTS["professor"])):
                start = time.perf_counter()
                code = _login_error(user, "wrong-" + secrets.token_hex(8))
                if code in CONNECTION_ERRORS:
                    raise LabUnavailable(f"Login attempts could not reach MariaDB ({code}); nothing was counted.")
                timings[label].append(milliseconds(start))
                groups[label].append(code)
        comparison = []
        for label, codes in groups.items():
            counts = {str(code): codes.count(code) for code in sorted(set(codes), key=str)}
            comparison.append({"label": label, "attempts": len(codes), "codes": counts,
                               "error_1045": codes.count(1045), "other": len(codes) - codes.count(1045),
                               "timing": summarize(timings[label])})
        leaks = sum(item["other"] for item in comparison)
        return {"kind": "codes", "runs": runs, "comparison": comparison,
                "headline": "no difference: every failed login answered 1045" if not leaks else
                            f"{leaks} attempts answered something other than 1045 (possible user-enumeration oracle)",
                "method": f"{runs} attempts per group, alternating: a random never-existing user name, then the real "
                          "account smith_professor, each with a random wrong password, over verified TLS. Records "
                          "the MariaDB error code of each failed login (README finding 12)."}

    def _bench_tls_versions(self, runs):
        """Cost of a new verified connection (TLS handshake + ED25519 login) with TLS 1.2 vs TLS 1.3."""
        versions = {"TLS 1.2": ssl.TLSVersion.TLSv1_2, "TLS 1.3": ssl.TLSVersion.TLSv1_3}
        samples = {label: [] for label in versions}
        negotiated = {}
        user = ACCOUNTS["student"]
        self._connect("student").close()   # makes sure the account is ready; not measured
        for version in versions.values():   # warm-up, not measured
            _tls_connection(user, version).close()
        for _ in range(runs):
            for label, version in versions.items():   # alternate, so drift affects both equally
                start = time.perf_counter()
                connection = _tls_connection(user, version)
                samples[label].append(milliseconds(start))
                if label not in negotiated:
                    negotiated[label] = dict(run_query(connection, "SHOW SESSION STATUS WHERE Variable_name IN "
                                                                   "('Ssl_version', 'Ssl_cipher')"))
                connection.close()
        return {"kind": "timing", "runs": runs, "unit": "ms",
                "comparison": [{"label": label, "negotiated": negotiated[label].get("Ssl_version"),
                                "cipher": negotiated[label].get("Ssl_cipher"), **summarize(values)}
                               for label, values in samples.items()],
                "series": [{"run": index + 1, **{label: round(samples[label][index], 3) for label in samples}}
                           for index in range(runs)],
                "headline": _faster("TLS 1.2", "TLS 1.3", samples),
                "method": f"{runs} new connections per TLS version as alice_student, alternating between the two, "
                          "after one unmeasured warm-up each. Each sample is the wall-clock time of "
                          "pymysql.connect(): TCP, TLS handshake with certificate and host-name verification, "
                          "ED25519 login. Plaintext is not a baseline: the server refuses it (3159)."}

    def _bench_privilege_paths(self, runs):
        """The same SELECT through four different privilege paths."""
        sql = "SELECT code, title FROM courses WHERE course_id = %s"
        paths = {
            "student": "table-level GRANT on courses",
            "professor": "database-level GRANT (+ DENY on another table)",
            "admin": "ALL PRIVILEGES on the database",
            "finance": "no privilege: refused with 1142",
        }
        connections = {role: self._connect(role) for role in paths}
        samples = {role: [] for role in paths}
        answers = {}
        try:
            for connection in connections.values():   # warm-up, not measured
                for _ in range(3):
                    _timed_select(connection, sql)
            for _ in range(runs):
                for role, connection in connections.items():
                    elapsed, answer = _timed_select(connection, sql)
                    samples[role].append(elapsed)
                    answers[role] = answer
        finally:
            for connection in connections.values():
                connection.close()
        return {"kind": "timing", "runs": runs, "unit": "ms",
                "comparison": [{"label": role, "path": path, "answer": answers[role], **summarize(samples[role])}
                               for role, path in paths.items()],
                "series": [{"run": index + 1, **{role: round(samples[role][index], 3) for role in paths}}
                           for index in range(runs)],
                "headline": _spread_headline(samples),
                "method": f"One open connection per role; {runs} executions of "
                          "`SELECT code, title FROM courses WHERE course_id = 101` each, round-robin across the roles, "
                          "after 3 unmeasured warm-ups. Each sample is execute + fetch "
                          "measured on the client, so it includes the network round trip to the container."}


SCENARIOS = {
    "access-matrix": {"title": "Access matrix: 4 roles x 6 actions",
                      "description": "What MariaDB allows and refuses for each role, checked against the "
                                     "documented policy.", "repeatable": False},
    "login-errors": {"title": "Failed logins: unknown user vs. wrong password",
                     "description": "Counts the error code of each failed login. Any code other than 1045 for "
                                    "unknown names would reveal which accounts exist (finding 12).",
                     "repeatable": True},
    "tls-versions": {"title": "Connection cost: TLS 1.2 vs TLS 1.3",
                     "description": "Time to open a new verified-TLS, ED25519-authenticated connection.",
                     "repeatable": True},
    "privilege-paths": {"title": "Same query, four privilege paths",
                        "description": "Latency of one SELECT for table-level, database-level and ALL grants, "
                                       "and for a refusal.", "repeatable": True},
}


def scenarios():
    return [{"id": key, **value} for key, value in SCENARIOS.items()]


def _login_error(user, password):
    """Try to log in; return the MariaDB error code (None if the login unexpectedly worked)."""
    try:
        connection = pymysql.connect(host=HOST, port=PORT, user=user, password=password, ssl=_tls_context(),
                                     connect_timeout=5)
    except pymysql.MySQLError as error:
        return error.args[0] if error.args else None
    connection.close()
    return None


def _tls_context(version=None):
    """A client TLS context that verifies the server certificate and host name against our CA."""
    if not TRUSTED_CA.is_file():
        raise ConfigError(f"CA certificate {TRUSTED_CA} not found. Run 'make certs'.")
    context = ssl.create_default_context(cafile=str(TRUSTED_CA))   # CERT_REQUIRED + check_hostname
    # Python 3.13 adds VERIFY_X509_STRICT to default contexts, which rejects our CA (no keyUsage
    # extension, see scripts/generate_certs.sh). The rest of the project verifies through PyMySQL's
    # ssl_ca option, which does not set that flag; the lab measures exactly that verification.
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if version is not None:
        context.minimum_version = context.maximum_version = version
    return context


def _tls_connection(user, version):
    return pymysql.connect(host=HOST, port=PORT, user=user, password=password_for(user), database="university",
                           ssl=_tls_context(version), connect_timeout=5)


def _timed_select(connection, sql):
    start = time.perf_counter()
    try:
        rows = run_query(connection, sql, (101,))
        answer = f"{len(rows)} row"
    except pymysql.MySQLError as error:
        answer = f"error {error.args[0]}"
    return milliseconds(start), answer


def _spread_headline(samples):
    medians = {label: statistics.median(values) for label, values in samples.items()}
    spread = max(statistics.stdev(values) for values in samples.values())
    gap = max(medians.values()) - min(medians.values())
    text = "median " + ", ".join(f"{label} {value:.2f} ms" for label, value in medians.items())
    verdict = "within" if gap <= spread else "larger than"
    return text + f": the largest gap ({gap:.2f} ms) is {verdict} the run-to-run spread (stdev up to {spread:.2f} ms)"


def _faster(first, second, samples):
    """A one-line comparison that does not claim more than the spread of the samples allows."""
    a, b = statistics.median(samples[first]), statistics.median(samples[second])
    spread = max(statistics.stdev(samples[first]), statistics.stdev(samples[second]))
    text = f"median {first} {a:.2f} ms, {second} {b:.2f} ms"
    if abs(a - b) <= spread:
        return text + f": the difference is within the run-to-run spread (stdev up to {spread:.2f} ms)"
    faster = first if a < b else second
    return text + f": {faster} is faster by {abs(a - b):.2f} ms on this machine, in this run"
