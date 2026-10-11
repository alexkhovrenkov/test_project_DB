"""
database.py - opens connections to the MariaDB server.

Every connection:
  * logs in with ED25519 authentication (PyMySQL handles this automatically
    when the account uses the ed25519 plugin; it needs the PyNaCl package),
  * uses TLS AND verifies the server's certificate against our CA, including
    the host name,
  * optionally presents the project's client certificate (for accounts created
    with REQUIRE X509, such as the harness account in admin.py).

Passwords are never read from a file. They are either typed by a person
(getpass) or set by admin.py at the start of an automated run and kept only
in this process's memory (remember_password).

There is deliberately NO permission logic in this file. Whatever the user is
allowed or not allowed to do is decided by MariaDB.
"""

import getpass
import os
import secrets
import sys
from pathlib import Path

import pymysql
from dotenv import load_dotenv

PROJECT_DIR = Path(__file__).resolve().parent.parent
CERTS_DIR = PROJECT_DIR / "certs"
TRUSTED_CA = CERTS_DIR / "ca.pem"
CLIENT_CERT = CERTS_DIR / "client-cert.pem"
CLIENT_KEY = CERTS_DIR / "client-key.pem"

# Optional, non-secret settings (port, container name) from .env.
load_dotenv(PROJECT_DIR / ".env")

HOST = os.environ.get("MARIADB_HOST", "localhost")   # must match the certificate
PORT = int(os.environ.get("MARIADB_PORT", "3306"))
CONTAINER = os.environ.get("MARIADB_CONTAINER", "university-db")

# Role name used on the command line -> MariaDB account
ACCOUNTS = {
    "student":   "alice_student",
    "professor": "smith_professor",
    "finance":   "jones_finance",
    "admin":     "uni_admin",
}

# Passwords known to THIS process only (never written anywhere).
_passwords = {}


class ConfigError(RuntimeError):
    """Something the user must fix before we can connect (missing certificates, ...)."""


def strong_password():
    """A random password that satisfies the server's password policy.

    token_urlsafe gives ~144 random bits from [A-Za-z0-9_-]; the fixed suffix
    guarantees an upper-case letter, a lower-case letter, a digit and a
    special character. Only those characters, so it is also safe to type.
    """
    return secrets.token_urlsafe(18) + "-Aa9"


def remember_password(user, password):
    _passwords[user] = password


def forget_password(user):
    _passwords.pop(user, None)


def password_for(user):
    """The password for `user`: remembered in memory, or typed by a person."""
    if user in _passwords:
        return _passwords[user]
    if not sys.stdin.isatty():
        raise ConfigError(f"no password known for {user}. Automated tools set them via admin.Harness; "
                          f"for interactive use run 'make set-password USER={user}' first.")
    _passwords[user] = getpass.getpass(f"Password for {user}: ")
    return _passwords[user]


def connect(user, password, host=HOST, ca_file=TRUSTED_CA, database="university", port=PORT,
            client_cert=False):
    """Open a TLS connection with full certificate verification.

    database=None connects without selecting a default database.
    client_cert=True also presents certs/client-cert.pem (for REQUIRE X509 accounts).
    """
    if not Path(ca_file).is_file():
        raise ConfigError(f"CA certificate {ca_file} not found. Run 'make certs'.")
    extra = {}
    if client_cert:
        if not CLIENT_KEY.is_file():
            raise ConfigError(f"client certificate {CLIENT_CERT} not found. Run 'make certs'.")
        extra = {"ssl_cert": str(CLIENT_CERT), "ssl_key": str(CLIENT_KEY)}
    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        autocommit=True,
        # --- TLS settings ---
        ssl_ca=str(ca_file),        # the CA we trust
        ssl_verify_cert=True,       # the certificate must be signed by that CA
        ssl_verify_identity=True,   # and must be issued for the host we connect to
        **extra,
    )


def connect_as(role):
    """Connect as the demo user for a role, e.g. connect_as("professor")."""
    user = ACCOUNTS[role]
    return connect(user, password_for(user))


def run_query(connection, sql, params=None):
    """Run one SQL statement and return the rows (empty list for UPDATE etc.).

    Always pass values through `params` (%s placeholders). The driver escapes
    each one and inserts it as a quoted literal, so a value can never change
    the meaning of the statement (PyMySQL escapes on the client; MariaDB's
    grammar would not accept a placeholder inside PASSWORD(...) anyway).
    """
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return cursor.fetchall()
