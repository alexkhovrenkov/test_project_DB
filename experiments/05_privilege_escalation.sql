-- @title Experiment 5: privilege escalation attempts
-- @goal Play an attacker who owns a low-privilege account (and one delegated administrator) and tries every common way to gain more.
-- @goal Record the exact error MariaDB returns for each attempt.

-- @phase setup
-- Initial configuration:
--   exp_low   : SELECT and INSERT on pub_t, plus CREATE and CREATE VIEW in exp_lab (so view and copy tricks are possible).
--   exp_priv  : a powerful role that exp_low was NEVER given (SELECT on all of exp_lab, DENY on secret_t).
--   exp_dba   : delegated administrator: SELECT on exp_lab WITH GRANT OPTION, but DENIED secret_t.
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_low@'%';
DROP USER IF EXISTS exp_dba@'%';
DROP USER IF EXISTS exp_other@'%';
DROP ROLE IF EXISTS exp_priv;
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.pub_t    (id INT PRIMARY KEY, v VARCHAR(20));
CREATE TABLE exp_lab.secret_t (id INT PRIMARY KEY, v VARCHAR(20));
INSERT INTO exp_lab.pub_t    VALUES (1, 'public');
INSERT INTO exp_lab.secret_t VALUES (1, 'top-secret');
CREATE ROLE exp_priv;
GRANT SELECT ON exp_lab.* TO exp_priv;
DENY SELECT ON exp_lab.secret_t TO exp_priv;
CREATE USER exp_low@'%'   IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
CREATE USER exp_dba@'%'   IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
CREATE USER exp_other@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT SELECT, INSERT ON exp_lab.pub_t TO exp_low@'%';
GRANT CREATE, CREATE VIEW ON exp_lab.* TO exp_low@'%';
GRANT SELECT ON exp_lab.* TO exp_dba@'%' WITH GRANT OPTION;
DENY SELECT ON exp_lab.secret_t TO exp_dba@'%';

-- @phase demo
-- @as exp_low
-- @why Baseline: the protected table is not readable.
-- @expect error 1142 secret_t
SELECT * FROM exp_lab.secret_t;

-- ===== Attacks on roles and grants =====
-- @why Attack 1: activate a role you were never granted. Error 1959: roles cannot be self-assigned.
-- @expect error 1959
SET ROLE exp_priv;

-- @why Attack 2: grant yourself the privilege. You cannot grant what you do not hold.
-- @expect error 1142
GRANT SELECT ON exp_lab.secret_t TO exp_low@'%';

-- @why Attack 3: grant to PUBLIC to open the door for everybody.
-- @expect error 1142
GRANT SELECT ON exp_lab.pub_t TO PUBLIC;

-- @why Attack 4: copy the protected data through a view you are allowed to create. A view needs SELECT on its base table at creation time.
-- @expect error 1142 secret_t
CREATE VIEW exp_lab.sneaky AS SELECT * FROM exp_lab.secret_t;

-- @why Attack 5: copy it into a table you CAN read. The source table is checked as well.
-- @expect error 1142 secret_t
INSERT INTO exp_lab.pub_t SELECT * FROM exp_lab.secret_t;

-- ===== Attacks on the account system =====
-- @expect error 1227
CREATE USER evil@'%' IDENTIFIED BY 'x';

-- @expect error 1142 global_priv
UPDATE mysql.global_priv SET Priv = '{}' WHERE User = 'exp_low';

-- @expect error 1142 user
SELECT * FROM mysql.user;

-- @why Attack 9: take over root by changing its password.
-- @expect error 1044
SET PASSWORD FOR root@'%' = PASSWORD('hacked');

-- ===== Attacks on the server and the file system =====
-- @expect error 1227
SELECT 'x' INTO OUTFILE '/tmp/exp_low_was_here';

-- @why LOAD_FILE does not raise an error without the FILE privilege; it silently returns NULL.
-- @expect contains NULL
SELECT LOAD_FILE('/etc/passwd');

-- @why Attack 12: load a shared library as a user-defined function (a classic route to code execution).
-- @expect error 1044
CREATE FUNCTION evil RETURNS INT SONAME 'evil.so';

-- @expect error 1227
SET GLOBAL read_only = 0;

-- ===== Attacks by a delegated administrator =====
-- @as exp_dba
-- @why Control: exp_dba may delegate what it holds. This works.
GRANT SELECT ON exp_lab.pub_t TO exp_other@'%';

-- @why Attack 14: exp_dba is DENIED secret_t but has GRANT OPTION on the whole database. Can it hand the table to someone else?
-- @expect error 1142 secret_t
GRANT SELECT ON exp_lab.secret_t TO exp_other@'%';

-- @why Attack 15: remove its own DENY. Lifting a DENY requires holding the denied privilege.
-- @expect error 1142 secret_t
REVOKE DENY SELECT ON exp_lab.secret_t FROM exp_dba@'%';

-- @takeaway No attempt succeeded, and every one failed with a different, specific error. The failures come from MariaDB's grant tables, not from application code.
-- @takeaway A DENY also constrains delegated administrators: GRANT OPTION does not let them hand out, or unlock for themselves, a privilege they are denied.

-- @phase cleanup
-- @as root
DROP DATABASE exp_lab;
DROP USER exp_low@'%';
DROP USER exp_dba@'%';
DROP USER exp_other@'%';
DROP ROLE exp_priv;
