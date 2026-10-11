"""
admin.py - administration without any stored password.

Three pieces:

* socket_sql()   runs SQL as MariaDB root through `docker exec ... mariadb`.
                 root@localhost authenticates with unix_socket: the operating
                 system user "root" inside the container IS the proof of
                 identity. There is no root password anywhere, and root has no
                 network account at all.

* Harness        a short-lived administrative account for one automated run
                 (tests, demo, experiments). It is created through socket_sql,
                 logs in over verified TLS with ED25519 + a random password that
                 exists only in this process's memory, is created REQUIRE X509
                 (it also needs certs/client-cert.pem), holds only the global
                 privileges the experiments need, and is dropped at the end.
                 Harness.activate_demo_accounts() gives the four demo accounts
                 fresh random passwords (in memory only) and unlocks them.

* set-password   python app/admin.py set-password smith_professor
                 asks for a password (getpass), sets it and unlocks the account.

How values reach SQL: MariaDB only accepts a string LITERAL inside
PASSWORD(...) - a server-side placeholder (?) or a variable (@pw) is a syntax
error (1064), verified on 13.1.2. So a password can only travel as an escaped
literal. Over a driver connection PyMySQL's %s parameters do exactly that.
Through `docker exec` there is no driver connection, so socket_sql() uses the
very same escaping function as the driver (pymysql.converters.escape_item),
and the SQL is sent on stdin, never on a command line. Identifiers (account
names) are either generated here (harness_<hex>) or checked against the fixed
list of demo accounts before they are formatted into a statement.
"""

import argparse
import getpass
import os
import re
import secrets
import subprocess
import sys

import pymysql
from pymysql.converters import escape_item

from database import (ACCOUNTS, CONTAINER, ConfigError, connect, remember_password, run_query,
                      strong_password)

DOCKER = os.environ.get("DOCKER", "docker")
DEMO_USERS = tuple(ACCOUNTS.values())

# Everything the tests and experiments need (create scratch databases, roles and
# accounts; GRANT/DENY with GRANT OPTION; FLUSH PRIVILEGES; read the mysql schema;
# create views for another definer) - and nothing that reaches the operating
# system or the server process: no FILE, SHUTDOWN, PROCESS, SUPER, replication
# or connection-admin privileges.
HARNESS_PRIVILEGES = (
    "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, RELOAD, REFERENCES, INDEX, ALTER, "
    "CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, "
    "ALTER ROUTINE, CREATE USER, EVENT, TRIGGER, SHOW DATABASES, SET USER, DELETE HISTORY, SHOW CREATE ROUTINE"
)
HARNESS_NAME = re.compile(r"^harness_[0-9a-f]{8}$")


class SocketSQLError(RuntimeError):
    """The mariadb client inside the container reported an error."""


def socket_sql(sql, params=(), container=CONTAINER):
    """Run SQL as root@localhost (unix_socket) inside the container; return output lines.

    `params` fill %s placeholders exactly like PyMySQL parameters do (same escaping
    function). As with PyMySQL, a literal % in `sql` is written %%.
    """
    sql = sql % tuple(escape_item(value, "utf8mb4") for value in params)
    command = [DOCKER, "exec", "-i", container, "mariadb", "--protocol=socket", "--user=root",
               "--batch", "--skip-column-names"]
    try:
        result = subprocess.run(command, input=sql, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise ConfigError("the docker command was not found. Install Docker / add it to PATH.") from None
    if result.returncode != 0:
        raise SocketSQLError(result.stderr.strip() or f"docker exec failed ({result.returncode})")
    return result.stdout.splitlines()


class Harness:
    """A short-lived administrative account (see the module docstring)."""

    def __init__(self):
        self.name = f"harness_{secrets.token_hex(4)}"
        self.password = strong_password()
        self._connection = None

    def __enter__(self):
        assert HARNESS_NAME.match(self.name)
        # Leftovers of runs that were killed before they could clean up.
        for stale in socket_sql("SELECT User FROM mysql.global_priv WHERE User LIKE 'harness\\_%%'"):
            if HARNESS_NAME.match(stale):
                socket_sql(f"DROP USER IF EXISTS `{stale}`@'%%'")
        socket_sql(f"CREATE USER `{self.name}`@'%%' IDENTIFIED VIA ed25519 USING PASSWORD(%s) REQUIRE X509",
                   (self.password,))
        socket_sql(f"GRANT {HARNESS_PRIVILEGES} ON *.* TO `{self.name}`@'%%' WITH GRANT OPTION")
        remember_password(self.name, self.password)
        return self

    def __exit__(self, *exc):
        if self._connection:
            self._connection.close()
        socket_sql(f"DROP USER IF EXISTS `{self.name}`@'%%'")

    def connect(self, **kwargs):
        """A NEW verified-TLS connection as the harness account (with the client certificate)."""
        kwargs.setdefault("database", None)
        return connect(self.name, self.password, client_cert=True, **kwargs)

    @property
    def connection(self):
        """One shared connection for administrative statements."""
        if self._connection is None:
            self._connection = self.connect()
        return self._connection

    def activate_demo_accounts(self):
        """Give every demo account a fresh random password (memory only) and unlock it."""
        for user in DEMO_USERS:
            password = strong_password()
            run_query(self.connection,
                      f"ALTER USER `{user}`@'%%' IDENTIFIED VIA ed25519 USING PASSWORD(%s) ACCOUNT UNLOCK",
                      (password,))
            remember_password(user, password)


def set_password(user):
    """Ask for a password twice and set it for one demo account (unlocking it)."""
    if user not in DEMO_USERS:
        raise SystemExit(f"Unknown account {user!r}. Choose one of: {', '.join(DEMO_USERS)}")
    first = getpass.getpass(f"New password for {user}: ")
    if first != getpass.getpass("Repeat it: "):
        raise SystemExit("The two passwords differ; nothing was changed.")
    try:
        socket_sql(f"ALTER USER `{user}`@'%%' IDENTIFIED VIA ed25519 USING PASSWORD(%s) ACCOUNT UNLOCK",
                   (first,))
    except SocketSQLError as error:
        raise SystemExit(f"MariaDB refused: {error}") from None
    print(f"Password set and account unlocked. Log in with: make sql USER={user}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Password-free administration helpers.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("set-password", help="set a demo account's password").add_argument("user")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "set-password":
            set_password(arguments.user)
    except (ConfigError, SocketSQLError, pymysql.MySQLError) as error:
        raise SystemExit(f"ERROR: {error}") from None


if __name__ == "__main__":
    sys.exit(main())
