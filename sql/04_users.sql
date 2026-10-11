-- 04_users.sql
-- Creates one MariaDB account per role - WITHOUT any password.
--
-- No password ever passes through these init scripts (or any file). Each
-- account is created LOCKED, with an ed25519 credential nobody can use: the
-- public key below belongs to 32 random bytes that were thrown away right
-- after the key was computed, so no password matches it.
-- An account becomes usable only when someone sets a real password AND
-- unlocks it in the same statement:
--   * automated runs (make demo / make test / CI): the short-lived harness
--     account sets a fresh random password, kept only in process memory;
--   * by hand: make set-password USER=smith_professor (asks for the password).

-- ED25519 is an authentication plugin. It ships with MariaDB but must be
-- loaded once. The server remembers it after restarts.
INSTALL SONAME 'auth_ed25519';

-- '%' means "may connect from any host" (we connect from outside the container).
CREATE USER 'alice_student'@'%'   IDENTIFIED VIA ed25519 USING 'Sv1MQTlVnCTyb4USqBdcQ87pFwhv7cbvwC5IIXBymhY' ACCOUNT LOCK;
CREATE USER 'smith_professor'@'%' IDENTIFIED VIA ed25519 USING 'Sv1MQTlVnCTyb4USqBdcQ87pFwhv7cbvwC5IIXBymhY' ACCOUNT LOCK;
CREATE USER 'jones_finance'@'%'   IDENTIFIED VIA ed25519 USING 'Sv1MQTlVnCTyb4USqBdcQ87pFwhv7cbvwC5IIXBymhY' ACCOUNT LOCK;
CREATE USER 'uni_admin'@'%'       IDENTIFIED VIA ed25519 USING 'Sv1MQTlVnCTyb4USqBdcQ87pFwhv7cbvwC5IIXBymhY' ACCOUNT LOCK;

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
