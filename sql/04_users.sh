#!/bin/bash
# 04_users.sh
# Creates one MariaDB account per role.
#
# This is a shell script instead of a .sql file because plain SQL cannot read
# environment variables, and we do NOT want passwords written in Git.
# The passwords come from .env -> docker-compose.yml -> this script.

set -euo pipefail

# The passwords are placed inside SQL quotes below, so they are validated
# first: only [A-Za-z0-9_-], at least 12 characters, and never a placeholder.
# (A password with a quote in it could otherwise break out of the SQL string.)
for variable in MARIADB_ROOT_PASSWORD STUDENT_PASSWORD PROFESSOR_PASSWORD FINANCE_PASSWORD ADMIN_PASSWORD; do
    value="${!variable:-}"
    if [[ ! "$value" =~ ^[A-Za-z0-9_-]{12,}$ ]]; then
        echo "ERROR: $variable must be at least 12 characters of letters, digits, - or _ (run 'make env')." >&2
        exit 1
    fi
    if [[ "$value" == change-me* ]]; then
        echo "ERROR: $variable is still the 'change-me' placeholder (run 'make env')." >&2
        exit 1
    fi
done

# The password goes in through the environment, not the command line, so it
# does not show up in the process list.
MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb --user=root <<SQL

-- ED25519 is an authentication plugin. It ships with MariaDB but must be
-- loaded once. The server remembers it after restarts.
INSTALL SONAME 'auth_ed25519';

-- IDENTIFIED VIA ed25519 USING PASSWORD('...'):
-- MariaDB turns the password into an ed25519 PUBLIC key and stores only that.
-- '%' means "may connect from any host" (we connect from outside the container).
CREATE USER 'alice_student'@'%'   IDENTIFIED VIA ed25519 USING PASSWORD('$STUDENT_PASSWORD');
CREATE USER 'smith_professor'@'%' IDENTIFIED VIA ed25519 USING PASSWORD('$PROFESSOR_PASSWORD');
CREATE USER 'jones_finance'@'%'   IDENTIFIED VIA ed25519 USING PASSWORD('$FINANCE_PASSWORD');
CREATE USER 'uni_admin'@'%'       IDENTIFIED VIA ed25519 USING PASSWORD('$ADMIN_PASSWORD');

-- Give each user their role...
GRANT student_role   TO 'alice_student'@'%';
GRANT professor_role TO 'smith_professor'@'%';
GRANT finance_role   TO 'jones_finance'@'%';
GRANT admin_role     TO 'uni_admin'@'%';

-- ...and make it active automatically when they log in.
-- (Without a default role, a user would have to run "SET ROLE ..." first.)
SET DEFAULT ROLE student_role   FOR 'alice_student'@'%';
SET DEFAULT ROLE professor_role FOR 'smith_professor'@'%';
SET DEFAULT ROLE finance_role   FOR 'jones_finance'@'%';
SET DEFAULT ROLE admin_role     FOR 'uni_admin'@'%';

-- The Docker image creates root with the older mysql_native_password plugin.
-- Switch root to ed25519 too, so EVERY password account uses the same method.
ALTER USER 'root'@'localhost' IDENTIFIED VIA ed25519 USING PASSWORD('$MARIADB_ROOT_PASSWORD');
ALTER USER 'root'@'%'         IDENTIFIED VIA ed25519 USING PASSWORD('$MARIADB_ROOT_PASSWORD');
SQL
