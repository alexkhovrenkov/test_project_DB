"""
test_lab.py - unit tests (no server) for the Interactive Lab backend: the playground's
statement check, value conversion, statistics, the example catalogue and the HTTP layer.
"""

import datetime
import http.client
import json
import signal
import threading
from decimal import Decimal

import pymysql
import pytest

import lab
import lab_server
from database import ACCOUNTS
from lab import LabError, LabUnavailable, auth_chain, check_statement, describe_error, summarize, to_json_value
from lab_examples import CATEGORIES, EXAMPLES

# --- the statement check -----------------------------------------------------------------------


@pytest.mark.parametrize("sql, kind", [
    ("SELECT 1", "read"),
    ("  select code from courses;  ", "read"),
    ("SHOW GRANTS", "read"),
    ("WITH t AS (SELECT 1) SELECT * FROM t", "read"),
    ("DESCRIBE grades", "read"),
    ("EXPLAIN SELECT * FROM grades", "read"),
    ("-- a comment\nSELECT 1", "read"),
    ("/* block */ SELECT 1", "read"),
    ("# hash comment\nSELECT 1", "read"),
    ("UPDATE grades SET grade = 1.0 WHERE grade_id = 1", "write"),
    ("INSERT INTO financial_records VALUES (9, 1, 1, 1, NULL, 'x')", "write"),
    ("DELETE FROM grades WHERE grade_id = 7", "write"),
])
def test_allowed_statements_are_classified(sql, kind):
    statement, actual = check_statement(sql)
    assert actual == kind
    assert not statement.endswith(";")


@pytest.mark.parametrize("sql", [
    "DROP TABLE grades",
    "GRANT SELECT ON *.* TO alice_student",
    "DENY SELECT ON university.courses TO student_role",
    "REVOKE DENY SELECT ON university.financial_records FROM professor_role",
    "SET ROLE NONE",
    "SET PASSWORD = PASSWORD('x')",
    "CREATE USER x",
    "ALTER USER alice_student ACCOUNT UNLOCK",
    "CALL some_procedure()",
    "LOAD DATA INFILE '/etc/passwd' INTO TABLE t",
    "TRUNCATE grades",
    "COMMIT",
    "",
    "   ",
    "-- only a comment",
])
def test_everything_else_is_refused(sql):
    with pytest.raises(LabError):
        check_statement(sql)


@pytest.mark.parametrize("sql", [
    "SELECT 1; DROP TABLE grades",
    "SELECT 1;\nSELECT 2;",
    "/*! DROP TABLE grades */ SELECT 1",
    "SELECT 1 /*M!100000 , SLEEP(1) */",
])
def test_multiple_and_hidden_statements_are_refused(sql):
    with pytest.raises(LabError):
        check_statement(sql)


def test_input_limits():
    with pytest.raises(LabError, match="longer"):
        check_statement("SELECT " + "1" * lab.MAX_SQL_LENGTH)
    with pytest.raises(LabError):
        check_statement(None)
    with pytest.raises(LabError):
        check_statement(42)


def test_every_preloaded_example_passes_the_check():
    for example in EXAMPLES:
        check_statement(example["sql"])


# --- conversions and statistics ----------------------------------------------------------------


def test_values_become_json_without_losing_precision():
    assert to_json_value(Decimal("1.30")) == "1.30"
    assert to_json_value(None) is None and to_json_value(5) == 5 and to_json_value("x") == "x"
    assert to_json_value(datetime.date(2026, 10, 19)) == "2026-10-19"
    assert to_json_value(datetime.timedelta(seconds=90)) == "0:01:30"
    assert to_json_value(b"abc") == "abc"
    assert to_json_value(b"\xff\x00") == "0xff00"
    json.dumps([to_json_value(value) for value in (Decimal("2"), datetime.datetime(2026, 1, 1), b"\x80", object())])


def test_summary_statistics():
    summary = summarize([4.0, 1.0, 3.0, 2.0, 100.0])
    assert summary["runs"] == 5 and summary["median"] == 3.0 and summary["min"] == 1.0 and summary["max"] == 100.0
    assert summary["mean"] == 22.0 and summary["p95"] == 100.0 and summary["stdev"] > 40
    assert summarize([7.0])["stdev"] == 0.0
    assert summarize([]) == {"runs": 0}


def test_runs_are_bounded():
    assert lab.bounded_runs(None) == 30
    assert lab.bounded_runs(1) == 5 and lab.bounded_runs(10_000) == 200 and lab.bounded_runs(42) == 42
    for bad in ("30", 3.5, True):
        with pytest.raises(LabError):
            lab.bounded_runs(bad)


def test_headlines_do_not_claim_more_than_the_spread():
    close = {"A": [5.0, 5.4, 4.6, 5.2], "B": [5.1, 5.5, 4.7, 5.3]}
    assert "within the run-to-run spread" in lab._faster("A", "B", close)
    apart = {"A": [5.0, 5.1, 4.9, 5.0], "B": [9.0, 9.1, 8.9, 9.0]}
    assert "A is faster by 4.00 ms" in lab._faster("A", "B", apart)
    assert "is within the run-to-run spread" in lab._spread_headline(close)
    assert "is larger than the run-to-run spread" in lab._spread_headline(apart)


def test_auth_chain_reads_the_or_chain_of_global_priv():
    assert auth_chain("ed25519", None) == ["ed25519"]
    assert auth_chain("ed25519", '[{"plugin": "unix_socket"}, {}]') == ["unix_socket", "ed25519"]
    assert auth_chain(None, None) == []


def test_error_codes_are_classified():
    denied = describe_error(pymysql.err.OperationalError(1142, "SELECT command denied"))
    assert denied["outcome"] == "denied" and denied["code"] == 1142 and denied["hint"]
    missing = describe_error(pymysql.err.ProgrammingError(1146, "Table doesn't exist"))
    assert missing["outcome"] == "error" and missing["hint"] == "the table does not exist"
    timeout = describe_error(pymysql.err.OperationalError(1969, "Query was interrupted"))
    assert "max_statement_time" in timeout["hint"]


# --- the example catalogue ---------------------------------------------------------------------


def test_examples_are_complete_and_consistent():
    categories = {key for key, _ in CATEGORIES}
    ids = [example["id"] for example in EXAMPLES]
    assert len(ids) == len(set(ids))
    for example in EXAMPLES:
        for field in ("id", "category", "title", "role", "sql", "feature", "what", "why", "observe", "expect"):
            assert example.get(field), f"{example['id']}: missing {field}"
        assert example["category"] in categories
        assert example["role"] in ACCOUNTS
        expect = example["expect"]
        assert expect["outcome"] in {"allowed", "denied", "error"}
        assert ("rows" in expect) == (expect["outcome"] == "allowed")
        assert ("error" in expect) == (expect["outcome"] != "allowed")
    assert {example["category"] for example in EXAMPLES} == categories


def test_examples_cover_the_area_capabilities():
    text = " ".join(example["sql"] + example["feature"] for example in EXAMPLES)
    for capability in ("DENY", "my_grades", "UPDATE", "Ssl_version", "ed25519", "require_secure_transport"):
        assert capability in text
    assert {example["role"] for example in EXAMPLES} == set(ACCOUNTS)
    assert {example["expect"]["outcome"] for example in EXAMPLES} == {"allowed", "denied", "error"}


def test_unknown_scenario_and_role_are_refused_before_any_connection():
    offline = lab.Lab()
    with pytest.raises(LabError, match="Unknown scenario"):
        offline.benchmark("nope")
    with pytest.raises(LabError, match="Unknown role"):
        offline._connect("root")


# --- the HTTP layer, with a stand-in for the database ------------------------------------------


class FakeLab:
    def health(self):
        return {"database": "up", "server_version": "test"}

    def examples(self):
        return {"examples": [], "categories": []}

    def stats(self):
        raise LabUnavailable("MariaDB is not answering")

    def run(self, role, sql):
        check_statement(sql)
        return {"ok": True, "role": role, "sql_seen": sql}

    def benchmark(self, scenario, runs=None):
        raise pymysql.err.OperationalError(1045, "Access denied")


@pytest.fixture
def server(tmp_path):
    (tmp_path / "index.html").write_text("<!doctype html><title>lab</title>")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("console.log(1)")
    (tmp_path.parent / "secret.txt").write_text("outside")
    httpd = lab_server.make_server(FakeLab(), port=0, dist_dir=tmp_path, quiet=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_port
    httpd.shutdown()
    httpd.server_close()


def call(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json", **(headers or {})}
    connection.request(method, path, body=json.dumps(body) if isinstance(body, dict) else body, headers=headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    try:
        return response.status, json.loads(data), response
    except json.JSONDecodeError:
        return response.status, data.decode(), response


def test_api_routes_and_status_codes(server):
    assert call(server, "GET", "/api/health")[:2] == (200, {"database": "up", "server_version": "test"})
    status, body, response = call(server, "POST", "/api/query", {"role": "student", "sql": "SELECT 1"})
    assert status == 200 and body["sql_seen"] == "SELECT 1"
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    assert response.getheader("Access-Control-Allow-Origin") is None
    status, body, _ = call(server, "POST", "/api/query", {"role": "student", "sql": "DROP TABLE grades"})
    assert status == 400 and "DROP" in body["error"]
    status, body, _ = call(server, "GET", "/api/stats")
    assert status == 503 and body["database"] == "down"
    assert call(server, "POST", "/api/benchmark", {"scenario": "x"})[0] == 502
    assert call(server, "GET", "/api/nope")[0] == 404
    assert call(server, "DELETE", "/api/health")[0] in (404, 405, 501)


def test_post_must_be_json(server):
    status, body, _ = call(server, "POST", "/api/query", "role=student", {"Content-Type": "text/plain"})
    assert status == 400 and "application/json" in body["error"]
    assert call(server, "POST", "/api/query", "{not json")[0] == 400
    assert call(server, "POST", "/api/query", "[1, 2]")[0] == 400
    big = json.dumps({"sql": "x" * (lab_server.MAX_BODY_BYTES + 1)})
    assert call(server, "POST", "/api/query", big)[0] == 400


def test_foreign_host_headers_are_refused(server):
    """DNS rebinding: a page on evil.example resolving to 127.0.0.1 must not reach the API."""
    assert call(server, "GET", "/api/health", headers={"Host": "evil.example"})[0] == 403
    assert call(server, "GET", "/api/health", headers={"Host": f"localhost:{server}"})[0] == 200


def test_static_files_and_single_page_fallback(server):
    status, body, response = call(server, "GET", "/assets/app.js")
    assert status == 200 and "console.log" in body
    assert "javascript" in response.getheader("Content-Type")
    status, body, _ = call(server, "GET", "/some/client/route")
    assert status == 200 and "<title>lab</title>" in body
    status, body, _ = call(server, "GET", "/../secret.txt")
    assert status in (200, 404) and "outside" not in str(body)


def test_missing_build_is_explained(tmp_path):
    httpd = lab_server.make_server(FakeLab(), port=0, dist_dir=tmp_path / "empty", quiet=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        status, body, _ = call(httpd.server_port, "GET", "/")
        assert status == 503 and "make lab" in body
    finally:
        httpd.shutdown()
        httpd.server_close()


# --- lifecycle: the lab's own harness, with stand-ins for Docker and MariaDB --------------------


class FakeHarness:
    """Stands in for admin.Harness: records what the lab did with it."""

    created = []
    fail_enter = None
    fail_activate = None

    def __init__(self):
        self.exited = False
        self.activations = 0
        self.connection = object()
        FakeHarness.created.append(self)

    def __enter__(self):
        if FakeHarness.fail_enter:
            raise FakeHarness.fail_enter
        return self

    def __exit__(self, *exc):
        self.exited = True
        raise lab.SocketSQLError("docker went away")   # must be swallowed by the lab

    def activate_demo_accounts(self):
        if FakeHarness.fail_activate:
            raise FakeHarness.fail_activate
        self.activations += 1


@pytest.fixture
def fake_harness(monkeypatch):
    FakeHarness.created, FakeHarness.fail_enter, FakeHarness.fail_activate = [], None, None
    monkeypatch.setattr(lab, "Harness", FakeHarness)
    return FakeHarness


def test_health_reports_docker_problems_instead_of_crashing(fake_harness):
    fake_harness.fail_enter = lab.ConfigError("the docker command was not found")
    health = lab.Lab().health()
    assert health["database"] == "down" and "docker exec" in health["error"] and "make up" in health["error"]
    fake_harness.fail_enter = pymysql.err.OperationalError(2003, "Can't connect")
    assert "not answering" in lab.Lab().health()["error"]


def test_failed_activation_drops_the_harness(fake_harness):
    fake_harness.fail_activate = pymysql.err.OperationalError(1396, "Operation ALTER USER failed")
    assert "demo accounts" in lab.Lab().health()["error"]
    assert fake_harness.created[0].exited


def test_lost_server_is_reported_and_the_harness_recreated(fake_harness, monkeypatch):
    answers = [pymysql.err.OperationalError(2013, "Lost connection"), [("13.1.2-MariaDB", "test")]]

    def run_query(connection, sql, params=None):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(lab, "run_query", run_query)
    the_lab = lab.Lab()
    assert "Lost the connection" in the_lab.health()["error"]
    assert the_lab.health()["database"] == "up"
    assert len(fake_harness.created) == 2 and fake_harness.created[0].exited


def test_other_admin_errors_are_not_hidden(fake_harness, monkeypatch):
    def run_query(connection, sql, params=None):
        raise pymysql.err.OperationalError(1142, "SELECT command denied")

    monkeypatch.setattr(lab, "run_query", run_query)
    with pytest.raises(pymysql.err.OperationalError):
        lab.Lab().stats()


def test_connect_reactivates_after_a_password_change_and_reports_a_dead_server(fake_harness, monkeypatch):
    errors = [pymysql.err.OperationalError(1045, "Access denied"), None]

    def connect_as(role):
        error = errors.pop(0)
        if error:
            raise error
        return f"connection as {role}"

    monkeypatch.setattr(lab, "connect_as", connect_as)
    the_lab = lab.Lab()
    assert the_lab._connect("student") == "connection as student"
    assert fake_harness.created[0].activations == 2   # once at start, once after the 1045

    errors[:] = [pymysql.err.OperationalError(1045, "Access denied")] * 2
    with pytest.raises(pymysql.err.OperationalError):
        the_lab._connect("student")

    errors[:] = [pymysql.err.OperationalError(2003, "Can't connect")]
    with pytest.raises(LabUnavailable, match="make up"):
        the_lab._connect("student")
    assert fake_harness.created[0].exited


def test_login_errors_abort_when_the_server_is_unreachable(fake_harness, monkeypatch):
    monkeypatch.setattr(lab, "_login_error", lambda user, password: 2003)
    with pytest.raises(LabUnavailable, match="nothing was counted"):
        lab.Lab().benchmark("login-errors", runs=5)


def test_close_removes_the_harness_and_tolerates_errors(fake_harness):
    the_lab = lab.Lab()
    with the_lab._lock:
        the_lab._ensure_harness()
    the_lab.close()
    assert fake_harness.created[0].exited and the_lab._harness is None


class StoppingServer:
    server_port = 0

    def serve_forever(self):
        raise KeyboardInterrupt

    def server_close(self):
        self.closed = True


@pytest.mark.parametrize("database", ["up", "down"])
def test_lab_server_main_starts_and_stops_cleanly(monkeypatch, capsys, database, tmp_path):
    closed = []

    class MainLab(FakeLab):
        def health(self):
            return {"database": "up", "server_version": "13.1.2"} if database == "up" else \
                {"database": "down", "error": "MariaDB is not answering"}

        def close(self):
            closed.append(True)

    monkeypatch.setattr(lab_server, "Lab", MainLab)
    monkeypatch.setattr(lab_server, "make_server", lambda the_lab, port: StoppingServer())
    monkeypatch.setattr(lab_server, "DIST_DIR", tmp_path)
    assert lab_server.main(["--port", "0"]) == 0
    out = capsys.readouterr().out
    assert "http://127.0.0.1:" in out and "make lab" in out and closed == [True]
    assert ("verified TLS" in out) == (database == "up")
    assert ("WARNING" in out) == (database == "down")
    assert signal.getsignal(signal.SIGTERM) is not lab_server._stop_on_sigterm   # handler restored


def test_sigterm_stops_the_lab_like_ctrl_c():
    with pytest.raises(KeyboardInterrupt):
        lab_server._stop_on_sigterm(signal.SIGTERM, None)
