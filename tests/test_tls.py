"""
test_tls.py - attacks on TLS.

Run:  python tests/test_tls.py
"""

import os
import ssl
import sys

import pymysql

from checks import expect_allowed, expect_blocked, summary
from database import CERTS_DIR, connect, run_query

CONNECT_ERROR = 2003            # client could not set up the connection
INSECURE_TRANSPORT = 3159       # server: "Connections using insecure transport are prohibited"

USER = "smith_professor"
PASSWORD = os.environ["PROFESSOR_PASSWORD"]


def run():
    print("\n--- TLS ---")

    def verified_tls_connection():
        connection = connect(USER, PASSWORD)
        status = dict(run_query(connection, "SHOW SESSION STATUS LIKE 'Ssl_version'"))
        assert status["Ssl_version"].startswith("TLS"), status
    expect_allowed("Correct CA + verification: encrypted connection succeeds",
                   verified_tls_connection)

    # Attack 1: the client is given a CA that did NOT sign the server's
    # certificate (the situation a client is in when it talks to an impostor).
    expect_blocked("Client trusts a different CA: connection refused",
                   lambda: connect(USER, PASSWORD, ca_file=CERTS_DIR / "untrusted-ca.pem"),
                   CONNECT_ERROR, "CERTIFICATE_VERIFY_FAILED")

    # Attack 2: the certificate is only valid for "localhost".
    expect_blocked("Host name not in the certificate (127.0.0.1): connection refused",
                   lambda: connect(USER, PASSWORD, host="127.0.0.1"),
                   CONNECT_ERROR, "CERTIFICATE_VERIFY_FAILED")

    # Attack 3: try to talk to the server without any encryption.
    expect_blocked("Plaintext (no TLS) connection: refused by the server",
                   lambda: pymysql.connect(host="localhost", user=USER, password=PASSWORD,
                                           ssl_disabled=True),
                   INSECURE_TRANSPORT)

    # Lesson, not an attack: encryption WITHOUT verification still connects,
    # even though the client trusts nothing. It would connect to an impostor
    # just as happily. This is "TLS assumed" instead of "TLS verified".
    def unverified_tls_connects():
        no_checks = ssl.create_default_context()
        no_checks.check_hostname = False
        no_checks.verify_mode = ssl.CERT_NONE
        pymysql.connect(host="localhost", user=USER, password=PASSWORD, ssl=no_checks)
    expect_allowed("Encryption with verification OFF connects anyway (why verification matters)",
                   unverified_tls_connects)


if __name__ == "__main__":
    run()
    sys.exit(summary())
