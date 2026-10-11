-- @title Experiment 11: database-name patterns - when a GRANT leaks and a DENY is ignored
-- @goal Test the documented rule that database names in GRANT and DENY are patterns ("_" and "%" are wildcards).
-- @goal See what that does to a GRANT with an unescaped underscore, and to a DENY written as a pattern.

-- @phase setup
-- Two databases whose names differ in the underscore positions: exp_lab_a and exp1lab1a.
DROP DATABASE IF EXISTS exp_lab_a;
DROP DATABASE IF EXISTS exp1lab1a;
DROP USER IF EXISTS exp_u@'%';
DROP USER IF EXISTS exp_v@'%';
CREATE DATABASE exp_lab_a;
CREATE DATABASE exp1lab1a;
CREATE TABLE exp_lab_a.s (id INT PRIMARY KEY, v VARCHAR(20));
CREATE TABLE exp1lab1a.s (id INT PRIMARY KEY, v VARCHAR(20));
INSERT INTO exp_lab_a.s VALUES (1, 'intended');
INSERT INTO exp1lab1a.s VALUES (1, 'NOT intended');
CREATE USER exp_u@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
CREATE USER exp_v@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
-- The administrator means "the database exp_lab_a" but forgets that "_" is a wildcard.
GRANT SELECT ON exp_lab_a.* TO exp_u@'%';

-- @phase demo
-- @as exp_u
-- @expect rows 1
SELECT * FROM exp_lab_a.s;

-- @why LIMITATION: each "_" matches any single character, so the grant also covers exp1lab1a - a database the administrator never meant to expose.
-- @expect rows 1
SELECT * FROM exp1lab1a.s;

-- @as root
-- @why Repair: escape the underscores with a backslash and grant again.
REVOKE SELECT ON exp_lab_a.* FROM exp_u@'%';
GRANT SELECT ON `exp\_lab\_a`.* TO exp_u@'%';

-- @as exp_u
-- @expect rows 1
SELECT * FROM exp_lab_a.s;

-- @expect error 1142 exp1lab1a
SELECT * FROM exp1lab1a.s;

-- ===== A DENY written as a pattern =====
-- @as root
GRANT SELECT ON `exp\_lab\_a`.* TO exp_v@'%';
DENY SELECT ON `exp\_lab%`.* TO exp_v@'%';

-- @as exp_v
-- @why LIMITATION: only the MOST SPECIFIC matching entry is consulted. The exact grant on exp_lab_a is more specific than the deny pattern exp_lab%, so the broad DENY is silently ignored.
-- @expect rows 1
SELECT * FROM exp_lab_a.s;

-- @as root
DENY SELECT ON `exp\_lab\_a`.* TO exp_v@'%';

-- @as exp_v
-- @why A DENY at the same (exact) database name does apply.
-- @expect error 1142 s
SELECT * FROM exp_lab_a.s;

-- @takeaway Escape "_" and "%" in database-level GRANT and DENY (`my\_db`.*), and test with SHOW GRANTS plus a real query.
-- @takeaway Never rely on a DENY pattern to override an exact-name grant; deny the exact database or table instead.

-- @phase cleanup
-- @as root
DROP DATABASE exp_lab_a;
DROP DATABASE exp1lab1a;
DROP USER exp_u@'%';
DROP USER exp_v@'%';
