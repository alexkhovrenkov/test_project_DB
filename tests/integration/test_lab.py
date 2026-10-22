"""
test_lab.py - the Interactive Lab backend against the real server: every preloaded
playground example must get exactly the answer its explanation documents, writes must
be rolled back, the limits must hold, and every benchmark scenario must produce real,
consistent results. Also drives the HTTP API end to end.
"""

import http.client
import json
import threading

import pytest

import lab_server
from database import ACCOUNTS, run_query, strong_password
from lab import MAX_ROWS, Lab, LabError
from lab_examples import EXAMPLES


@pytest.fixture(scope="module")
def lab(harness):
    return Lab(harness)


def observed(result):
    if result["outcome"] == "allowed":
        return {"outcome": "allowed", "rows": result["row_count"]}
    return {"outcome": result["outcome"], "error": result["error"]["code"]}


@pytest.mark.parametrize("example", EXAMPLES, ids=[example["id"] for example in EXAMPLES])
def test_every_example_gets_the_documented_answer(lab, example):
    result = lab.run(example["role"], example["sql"])
    assert observed(result) == example["expect"], result
    assert result["account"] == f"{ACCOUNTS[example['role']]}@%"
    assert result["active_role"] == f"{example['role']}_role"
    assert result["elapsed_ms"] >= 0


def test_writes_are_rolled_back(lab, dba):
    before = run_query(dba, "SELECT grade_id, grade FROM university.grades ORDER BY grade_id")
    assert lab.run("professor", "UPDATE grades SET grade = 5.0 WHERE grade_id = 1")["affected_rows"] == 1
    assert lab.run("admin", "DELETE FROM grades WHERE grade_id = 7")["rolled_back"] is True
    inserted = lab.run("finance", "INSERT INTO financial_records VALUES (99, 1, 1.00, 0.00, NULL, 'XX00')")
    assert inserted["outcome"] == "allowed" and inserted["affected_rows"] == 1
    assert run_query(dba, "SELECT grade_id, grade FROM university.grades ORDER BY grade_id") == before
    assert run_query(dba, "SELECT COUNT(*) FROM university.financial_records WHERE record_id = 99")[0][0] == 0


def test_the_same_statement_differs_by_role(lab):
    answers = {role: observed(lab.run(role, "SELECT bank_iban FROM financial_records")) for role in ACCOUNTS}
    assert answers == {
        "student": {"outcome": "denied", "error": 1142},
        "professor": {"outcome": "denied", "error": 1142},   # the DENY
        "finance": {"outcome": "allowed", "rows": 5},
        "admin": {"outcome": "allowed", "rows": 5},
    }


def test_statement_timeout_is_enforced_by_the_server(lab):
    result = lab.run("student", "SELECT SLEEP(30)")
    assert result["outcome"] == "error" and result["error"]["code"] == 1969
    assert result["elapsed_ms"] < 10_000


def test_row_limit(lab):
    result = lab.run("student", "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 500) "
                                "SELECT i FROM n")
    assert result["truncated"] is True and len(result["rows"]) == MAX_ROWS


def test_refused_statements_never_reach_the_server(lab):
    with pytest.raises(LabError):
        lab.run("admin", "DROP TABLE grades")
    with pytest.raises(LabError):
        lab.run("admin", "SELECT 1; DROP TABLE grades")
    assert lab.run("admin", "SELECT COUNT(*) FROM grades")["rows"] == [[7]]


def test_lab_recovers_when_another_tool_changes_the_demo_passwords(lab, harness):
    """make test / make demo give the demo accounts new passwords while the lab runs."""
    user = ACCOUNTS["student"]
    run_query(harness.connection, f"ALTER USER `{user}`@'%%' IDENTIFIED VIA ed25519 USING PASSWORD(%s)",
              (strong_password(),))
    assert lab.run("student", "SELECT 1")["outcome"] == "allowed"


def test_health_and_stats_are_real(lab):
    health = lab.health()
    assert health["database"] == "up" and health["server_version"].startswith("13.1")
    stats = lab.stats()
    assert {table["name"]: table["rows"] for table in stats["tables"]} == {
        "students": 5, "courses": 4, "grades": 7, "financial_records": 5}
    accounts = {account["user"]: account for account in stats["accounts"]}
    assert accounts["root"]["auth_chain"] == ["unix_socket", "ed25519"]
    for user in ACCOUNTS.values():
        assert accounts[user]["auth_chain"] == ["ed25519"]
    assert accounts["professor_role"]["is_role"] and accounts["professor_role"]["denies"] == 1
    assert not any(name.startswith("harness_") for name in accounts)
    assert stats["server"]["require_secure_transport"] == "ON"
    assert stats["session_tls"]["version"] in {"TLSv1.2", "TLSv1.3"}
    assert {plugin["name"] for plugin in stats["plugins"]} >= {"ed25519", "unix_socket", "simple_password_check",
                                                                "password_reuse_check"}


def test_access_matrix_matches_the_documented_policy(lab):
    result = lab.benchmark("access-matrix")
    assert len(result["cells"]) == 24 and all(cell["match"] for cell in result["cells"])
    assert {row["label"]: (row["allowed"], row["denied"]) for row in result["comparison"]} == {
        "student": (2, 4), "professor": (5, 1), "finance": (2, 4), "admin": (6, 0)}
    assert result["headline"].startswith("24/24")


def test_failed_logins_all_answer_1045(lab):
    """Finding 12, live: unknown names and wrong passwords must be indistinguishable."""
    result = lab.benchmark("login-errors", runs=20)
    for group in result["comparison"]:
        assert group["attempts"] == 20 and group["codes"] == {"1045": 20}
    assert result["headline"].startswith("no difference")


def test_tls_versions_are_really_negotiated(lab):
    result = lab.benchmark("tls-versions", runs=5)
    negotiated = {item["label"]: item["negotiated"] for item in result["comparison"]}
    assert negotiated == {"TLS 1.2": "TLSv1.2", "TLS 1.3": "TLSv1.3"}
    assert len(result["series"]) == 5 and all(item["median"] > 0 for item in result["comparison"])


def test_privilege_paths_report_each_answer(lab):
    result = lab.benchmark("privilege-paths", runs=5)
    answers = {item["label"]: item["answer"] for item in result["comparison"]}
    assert answers == {"student": "1 row", "professor": "1 row", "admin": "1 row", "finance": "error 1142"}
    assert all(item["runs"] == 5 for item in result["comparison"])


def test_tls_benchmark_still_verifies_the_server(lab, tmp_path, monkeypatch):
    """The benchmark's own TLS context must refuse a server certificate from another CA."""
    import subprocess

    import lab as lab_module
    key, cert = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
                    "-days", "1", "-subj", "/CN=Other CA"], check=True, capture_output=True)
    monkeypatch.setattr(lab_module, "TRUSTED_CA", cert)
    code = lab_module._login_error(ACCOUNTS["student"], "irrelevant")
    assert code == 2003   # the TLS handshake fails before any login


def test_http_api_end_to_end(lab):
    httpd = lab_server.make_server(lab, port=0, quiet=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", httpd.server_port, timeout=30)
        connection.request("POST", "/api/query", body=json.dumps({"role": "professor",
                                                                  "sql": "SELECT * FROM financial_records"}),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        body = json.loads(response.read())
        assert response.status == 200 and body["error"]["code"] == 1142 and body["outcome"] == "denied"
        connection.request("GET", "/api/examples")
        response = connection.getresponse()
        assert len(json.loads(response.read())["examples"]) == len(EXAMPLES)
        connection.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_no_password_reaches_the_api(lab):
    """The browser never receives a credential: no remembered password appears in any answer."""
    from database import _passwords
    secrets_now = list(_passwords.values())
    text = json.dumps([lab.health(), lab.examples(), lab.stats(), lab.run("student", "SHOW GRANTS")])
    assert secrets_now and not any(secret in text for secret in secrets_now)


def test_a_lab_without_a_harness_creates_and_removes_its_own():
    """How make lab runs: the lab creates its own short-lived administrator, and drops it on exit."""
    from admin import socket_sql
    own = Lab()
    assert own.health()["database"] == "up"
    assert own.run("finance", "SELECT COUNT(*) FROM financial_records")["rows"] == [[5]]
    name = own._harness.name
    assert socket_sql("SELECT COUNT(*) FROM mysql.global_priv WHERE User = %s", (name,)) == ["1"]
    own.close()
    assert socket_sql("SELECT COUNT(*) FROM mysql.global_priv WHERE User = %s", (name,)) == ["0"]
