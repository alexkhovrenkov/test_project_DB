"""
database.py - opens connections to the MariaDB server.

Every connection:
  * logs in with ED25519 authentication (PyMySQL handles this automatically
    when the account uses the ed25519 plugin; it needs the PyNaCl package),
  * uses TLS AND verifies the server's certificate against our CA.

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

# Role name used on the command line -> (MariaDB account, variable holding its password)
ACCOUNTS = {
    "student":   ("alice_student",   "STUDENT_PASSWORD"),
    "professor": ("smith_professor", "PROFESSOR_PASSWORD"),
    "finance":   ("jones_finance",   "FINANCE_PASSWORD"),
    "admin":     ("uni_admin",       "ADMIN_PASSWORD"),
}


def connect(user, password, host="localhost", ca_file=TRUSTED_CA):
    """Open a TLS connection with full certificate verification."""
    return pymysql.connect(
        host=host,
        port=3306,
        user=user,
        password=password,
        database="university",
        # --- TLS settings ---
        ssl_ca=str(ca_file),        # the CA we trust
        ssl_verify_cert=True,       # the certificate must be signed by that CA
        ssl_verify_identity=True,   # and must be issued for the host we connect to
    )


def connect_as(role):
    """Connect as the demo user for a role, e.g. connect_as("professor")."""
    user, password_variable = ACCOUNTS[role]
    return connect(user, os.environ[password_variable])


def run_query(connection, sql, params=None):
    """Run one SQL statement and return the rows (empty list for UPDATE etc.)."""
    with connection.cursor() as cursor:
        cursor.execute(sql, params)   # params are sent separately -> no SQL injection
        connection.commit()
        return cursor.fetchall()
