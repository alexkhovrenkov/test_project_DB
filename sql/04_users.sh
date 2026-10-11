#!/bin/bash
# 04_users.sh
# Creates one MariaDB account per role.
#
# This is a shell script instead of a .sql file because plain SQL cannot read
# environment variables, and we do NOT want passwords written in Git.
# The passwords come from .env -> docker-compose.yml -> this script.
#
# (Keep the passwords simple: letters, digits, - and _ only, since they are
#  placed inside SQL quotes below.)

mariadb --user=root --password="$MARIADB_ROOT_PASSWORD" <<SQL

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
