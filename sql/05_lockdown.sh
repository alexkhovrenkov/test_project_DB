#!/bin/bash
# 05_lockdown.sh - the last init step: leave no password anywhere.
#
# The image's entrypoint (started with MARIADB_ALLOW_EMPTY_ROOT_PASSWORD and
# MARIADB_ROOT_HOST=localhost, see docker-compose.yml) creates root@localhost
# with an EMPTY password, only reachable through the local socket while the
# temporary init server runs with --skip-networking. Here we:
#   1. switch root@localhost to unix_socket: only the operating-system user
#      "root" inside the container (docker exec) can log in as root, and
#      there is no password to steal, guess or leak;
#   2. remove the image's "healthcheck" accounts and the file that stores
#      their random password (/var/lib/mysql/.my-healthcheck.cnf).
#      healthcheck.sh then connects as the OS user root via the socket.
# The SQL below is fixed text (quoted heredoc): nothing is interpolated.

set -euo pipefail

mariadb --protocol=socket --user=root <<'SQL'
DROP USER IF EXISTS 'healthcheck'@'127.0.0.1', 'healthcheck'@'::1', 'healthcheck'@'localhost';
ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket;
SQL

rm -f /var/lib/mysql/.my-healthcheck.cnf
