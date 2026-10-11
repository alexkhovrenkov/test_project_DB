"""
database.py - opens connections to the MariaDB server.

Every connection:
  * logs in with ED25519 authentication (PyMySQL handles this automatically
    when the account uses the ed25519 plugin; it needs the PyNaCl package),
  * uses TLS AND verifies the server's certificate against our CA, including
    the host name.

There is deliberately NO permission logic in this file. Whatever the user is
allowed or not allowed to do is decided by MariaDB.
"""

import os
from pathlib import Path

import pymysql
from dotenv import load_dotenv

PROJECT_DIR = Path(__file__).resolve().parent.parent
CERTS_DIR = PROJECT_DIR / "certs"
TRUSTED_CA = CERTS_DIR / "ca.pem"

# Read the passwords from the .env file into environment variables.
load_dotenv(PROJECT_DIR / ".env")

HOST = os.environ.get("MARIADB_HOST", "localhost")   # must match the certificate
PORT = int(os.environ.get("MARIADB_PORT", "3306"))

# Role name used on the command line -> (MariaDB account, variable holding its password)
ACCOUNTS = {
    "student":   ("alice_student",   "STUDENT_PASSWORD"),
    "professor": ("smith_professor", "PROFESSOR_PASSWORD"),
    "finance":   ("jones_finance",   "FINANCE_PASSWORD"),
    "admin":     ("uni_admin",       "ADMIN_PASSWORD"),
}


class ConfigError(RuntimeError):
    """Something the user must fix before we can connect (missing .env, ...)."""


def password_from_env(variable):
    """Read a password from the environment, with a helpful error if it is missing."""
    try:
        return os.environ[variable]
    except KeyError:
        raise ConfigError(f"{variable} is not set. Run 'make env' to create .env.") from None


def connect(user, password, host=HOST, ca_file=TRUSTED_CA, database="university", port=PORT):
    """Open a TLS connection with full certificate verification.

    database=None connects without selecting a default database.
    """
    if not Path(ca_file).is_file():
        raise ConfigError(f"CA certificate {ca_file} not found. Run 'make certs'.")
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
    )


def connect_as(role):
    """Connect as the demo user for a role, e.g. connect_as("professor")."""
    user, password_variable = ACCOUNTS[role]
    return connect(user, password_from_env(password_variable))


def connect_root(**kwargs):
    """Connect as the database superuser (setup, tests and admin experiments)."""
    return connect("root", password_from_env("MARIADB_ROOT_PASSWORD"), **kwargs)


def run_query(connection, sql, params=None):
    """Run one SQL statement and return the rows (empty list for UPDATE etc.).

    Always pass user-controlled values through `params` (%s placeholders). They
    are sent separately from the SQL text, so they can never change its meaning.
    """
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return cursor.fetchall()
