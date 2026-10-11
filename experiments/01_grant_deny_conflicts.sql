-- @title Experiment 1: GRANT and DENY conflicts
-- @goal Find out which wins when GRANT and DENY disagree: at the same level, at different levels, and in either order.
-- @goal Check that a DENY only removes the privilege it names.
-- The MariaDB 13.1 DENY documentation says: a deny beats a grant at any level; the order of the statements does not
-- matter; a deny masks grants below it (database > table > column). This experiment tests each claim on the real server.

-- @phase setup
-- Initial configuration: database exp_lab with two tables, one role, one user holding that role.
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_u@'%';
DROP ROLE IF EXISTS exp_r;
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.t1 (id INT PRIMARY KEY, pub VARCHAR(20), secret VARCHAR(20));
CREATE TABLE exp_lab.t2 (id INT PRIMARY KEY, v VARCHAR(20));
INSERT INTO exp_lab.t1 VALUES (1, 'public-1', 'secret-1');
INSERT INTO exp_lab.t2 VALUES (1, 'value-1');
CREATE ROLE exp_r;
CREATE USER exp_u@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT exp_r TO exp_u@'%';
SET DEFAULT ROLE exp_r FOR exp_u@'%';

-- ===== Case A: broad GRANT, then DENY one table =====
GRANT SELECT ON exp_lab.* TO exp_r;
-- @phase demo
-- @as root
DENY SELECT ON exp_lab.t1 TO exp_r;

-- @as exp_u
-- @why Case A: GRANT on the whole database + DENY on t1. The DENY is more specific AND stronger.
-- @expect error 1142 t1
SELECT * FROM exp_lab.t1;

-- @why The other table is still covered by the database-level GRANT.
-- @expect rows 1
SELECT * FROM exp_lab.t2;

-- ===== Case B: order of statements =====
-- @phase setup
-- @as root
REVOKE ALL PRIVILEGES, GRANT OPTION FROM exp_r;
-- @phase demo
-- @as root
DENY SELECT ON exp_lab.t2 TO exp_r;
GRANT SELECT ON exp_lab.t2 TO exp_r;

-- @as exp_u
-- @why Case B: DENY first, GRANT afterwards. Still denied: the order of the two statements is irrelevant.
-- @expect error 1142 t2
SELECT * FROM exp_lab.t2;

-- ===== Case C: DENY at database level masks a GRANT at table level =====
-- @phase setup
-- @as root
REVOKE ALL PRIVILEGES, GRANT OPTION FROM exp_r;
-- @phase demo
-- @as root
GRANT SELECT ON exp_lab.t1 TO exp_r;
DENY SELECT ON exp_lab.* TO exp_r;

-- @as exp_u
-- @why Case C: the table-level GRANT on t1 is more specific, yet the database-level DENY still wins. Denies propagate downward.
-- @expect error 1142 t1
SELECT * FROM exp_lab.t1;

-- ===== Case D: DENY at table level masks a GRANT at column level =====
-- @phase setup
-- @as root
REVOKE ALL PRIVILEGES, GRANT OPTION FROM exp_r;
-- @phase demo
-- @as root
GRANT SELECT (pub) ON exp_lab.t1 TO exp_r;
DENY SELECT ON exp_lab.t1 TO exp_r;

-- @as exp_u
-- @why Case D: even the narrowest GRANT (one column) cannot survive a table-level DENY (reported as a table-level refusal, 1142).
-- @expect error 1142 t1
SELECT pub FROM exp_lab.t1;

-- ===== Case E: a DENY only removes what it names =====
-- @phase setup
-- @as root
REVOKE ALL PRIVILEGES, GRANT OPTION FROM exp_r;
-- @phase demo
-- @as root
GRANT SELECT, INSERT ON exp_lab.t2 TO exp_r;
DENY INSERT ON exp_lab.t2 TO exp_r;

-- @as exp_u
-- @why Case E: SELECT was granted and never denied, so reading still works.
-- @expect rows 1
SELECT * FROM exp_lab.t2;

-- @why INSERT was granted and denied: the DENY wins for exactly this privilege.
-- @expect error 1142 t2
INSERT INTO exp_lab.t2 VALUES (2, 'value-2');

-- @takeaway A DENY is a hard ceiling: broad GRANTs, later GRANTs and narrower GRANTs cannot raise a user above it.
-- @takeaway The flip side: an accidental DENY cannot be fixed by granting more. Only REVOKE DENY (at the same level) repairs it.

-- @phase cleanup
-- @as root
DROP DATABASE exp_lab;
DROP USER exp_u@'%';
DROP ROLE exp_r;
