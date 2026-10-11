"""
test_tls.py - attacks on TLS: the connection must be encrypted AND the server verified.
"""

import ssl

import pymysql
import pytest

from conftest import error_code
from database import CERTS_DIR, PORT, connect, password_for, run_query

CONNECT_ERROR = 2003            # client could not set up the connection
INSECURE_TRANSPORT = 3159       # server: "Connections using insecure transport are prohibited"

USER = "smith_professor"


@pytest.fixture(scope="module")
def password():
    return password_for(USER)


def message_of(callable_):
    try:
        callable_()
    except pymysql.MySQLError as error:
        return str(error.args[1])
    pytest.fail("connection succeeded but should have been refused")


def test_verified_connection_uses_modern_tls(password):
    connection = connect(USER, password)
    try:
        status = dict(run_query(connection, "SHOW SESSION STATUS WHERE Variable_name IN ('Ssl_version', 'Ssl_cipher')"))
    finally:
        connection.close()
    assert status["Ssl_version"] in ("TLSv1.2", "TLSv1.3")
    assert status["Ssl_cipher"]


def test_server_only_offers_tls_1_2_and_1_3(dba):
    assert run_query(dba, "SHOW VARIABLES LIKE 'tls_version'")[0][1] == "TLSv1.2,TLSv1.3"


def test_server_requires_secure_transport(dba):
    assert run_query(dba, "SHOW VARIABLES LIKE 'require_secure_transport'")[0][1] == "ON"


def test_client_trusting_a_different_ca_refuses_the_server(password):
    wrong_ca = CERTS_DIR / "untrusted-ca.pem"
    assert error_code(lambda: connect(USER, password, ca_file=wrong_ca)) == CONNECT_ERROR
    assert "CERTIFICATE_VERIFY_FAILED" in message_of(lambda: connect(USER, password, ca_file=wrong_ca))


def test_host_name_mismatch_is_refused(password):
    """The certificate is valid for 'localhost' only; connecting to the IP must fail verification."""
    text = message_of(lambda: connect(USER, password, host="127.0.0.1"))
    assert "CERTIFICATE_VERIFY_FAILED" in text and "mismatch" in text.lower()


def test_correct_host_name_is_accepted(password):
    connect(USER, password, host="localhost").close()


def test_plaintext_connection_is_refused_by_the_server(password):
    assert error_code(lambda: pymysql.connect(host="localhost", port=PORT, user=USER, password=password,
                                              ssl_disabled=True)) == INSECURE_TRANSPORT


def test_plaintext_connection_is_refused_for_the_administrator_too(harness):
    """Even the harness administrator, with its client certificate, cannot skip TLS."""
    assert error_code(lambda: pymysql.connect(
        host="localhost", port=PORT, user=harness.name, password=harness.password,
        ssl_disabled=True)) == INSECURE_TRANSPORT


def test_encryption_without_verification_connects_to_anyone(password):
    """The lesson, not a defence: with verification OFF the client would accept an impostor too."""
    no_checks = ssl.create_default_context()
    no_checks.check_hostname = False
    no_checks.verify_mode = ssl.CERT_NONE
    pymysql.connect(host="localhost", port=PORT, user=USER, password=password, ssl=no_checks).close()


def test_pymysql_default_encrypts_but_does_not_verify(password):
    """The reason this project sets ssl_verify_cert / ssl_verify_identity explicitly.

    With NO TLS options, PyMySQL 1.2 uses "preferred" mode: it encrypts, but trusts any
    certificate and any host name. The connection below is encrypted yet would equally
    reach an impostor server."""
    connection = pymysql.connect(host="localhost", port=PORT, user=USER, password=password)
    try:
        version = dict(run_query(connection, "SHOW SESSION STATUS LIKE 'Ssl_version'"))["Ssl_version"]
        assert version.startswith("TLS")
        assert connection.ctx.verify_mode == ssl.CERT_NONE and connection.ctx.check_hostname is False
    finally:
        connection.close()
