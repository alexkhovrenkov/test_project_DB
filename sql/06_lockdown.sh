#!/bin/bash
# 06_lockdown.sh - the last init step: leave no password anywhere.
#
# The image's entrypoint (started with MARIADB_ALLOW_EMPTY_ROOT_PASSWORD and
# MARIADB_ROOT_HOST=localhost, see docker-compose.yml) creates root@localhost
# with an EMPTY password, only reachable through the local socket while the
# temporary init server runs with --skip-networking. Here we:
#
#   1. switch root@localhost to
#        IDENTIFIED VIA unix_socket OR ed25519 USING '<unusable public key>'
#      Only the operating-system user "root" inside the container (docker
#      exec) can log in as root - through unix_socket. The ed25519 alternative
#      can never succeed (the key belongs to a discarded random secret, as in
#      04_users.sql); it is there so that ed25519, not unix_socket, is the
#      account's main plugin. Why that matters: for a login attempt with an
#      UNKNOWN user name, MariaDB imitates the plugin of a random existing
#      account. If that is unix_socket, the attempt fails with error 1698
#      instead of 1045, and since real network accounts always fail with 1045,
#      a single 1698 proves the name does not exist (user enumeration). With
#      unix_socket as the only method of root, about 1 in 13 attempts gave 1698;
#      with this order, none (see tests/test_account_model.py and finding 12).
#      strict_password_validation (active since 05_password_policy.sql) refuses
#      a ready-made key, so it is switched off for this single statement; the
#      init server has no network connections, nobody else is connected.
#   2. remove the image's "healthcheck" accounts and the file that stores
#      their random password (/var/lib/mysql/.my-healthcheck.cnf).
#      healthcheck.sh then connects as the OS user root via the socket.
#
# The SQL below is fixed text (quoted heredoc): nothing is interpolated.

set -euo pipefail

mariadb --protocol=socket --user=root <<'SQL'
DROP USER IF EXISTS 'healthcheck'@'127.0.0.1', 'healthcheck'@'::1', 'healthcheck'@'localhost';
SET GLOBAL strict_password_validation = OFF;
ALTER USER 'root'@'localhost'
    IDENTIFIED VIA unix_socket OR ed25519 USING 'Sv1MQTlVnCTyb4USqBdcQ87pFwhv7cbvwC5IIXBymhY';
SET GLOBAL strict_password_validation = ON;
SQL

rm -f /var/lib/mysql/.my-healthcheck.cnf
