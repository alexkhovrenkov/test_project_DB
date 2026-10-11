-- @title Example 2: DENY and REVOKE DENY (MariaDB 13.1)
-- @goal Grant broadly, then subtract one table with DENY.
-- @goal See that a later GRANT cannot undo a DENY, and that only REVOKE DENY can.
-- Run it with:  python app/sqlrunner.py examples/02_deny.sql

-- @phase setup
DROP DATABASE IF EXISTS tutorial;
DROP USER IF EXISTS tut_ann@'%';
DROP ROLE IF EXISTS tut_analyst;
CREATE DATABASE tutorial;
CREATE TABLE tutorial.projects  (id INT PRIMARY KEY, name VARCHAR(40));
CREATE TABLE tutorial.employees (id INT PRIMARY KEY, name VARCHAR(40), salary INT);
INSERT INTO tutorial.projects  VALUES (1, 'Apollo'), (2, 'Gemini');
INSERT INTO tutorial.employees VALUES (1, 'Ann', 5200), (2, 'Bob', 4800);
CREATE ROLE tut_analyst;
CREATE USER tut_ann@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT tut_analyst TO tut_ann@'%';
SET DEFAULT ROLE tut_analyst FOR tut_ann@'%';
-- "Everything in the database ..."
GRANT SELECT ON tutorial.* TO tut_analyst;

-- @phase demo
-- @as tut_ann
-- @why Before the DENY, the broad GRANT lets the analyst read every table.
-- @expect rows 2
SELECT * FROM tutorial.employees;

-- ... "except the employees table". One statement, no list of allowed tables.
-- @as root
DENY SELECT ON tutorial.employees TO tut_analyst;

-- @as root
-- @why DENY shows up as its own line in SHOW GRANTS (visible to accounts that can read the mysql database).
-- @expect contains DENY SELECT
SHOW GRANTS FOR tut_analyst;

-- @as tut_ann
-- @why Error 1142 = "command denied for table". The GRANT on tutorial.* is still there, but DENY wins.
-- @expect error 1142 employees
SELECT * FROM tutorial.employees;

-- @why The DENY only names SELECT on employees: other tables are unaffected.
-- @expect rows 2
SELECT * FROM tutorial.projects;

-- @why A denied table disappears from SHOW TABLES: the user cannot even see it exists.
-- @expect rows 1
SHOW TABLES FROM tutorial;

-- The administrator now tries to "fix" it with a more specific GRANT.
-- @as root
GRANT SELECT ON tutorial.employees TO tut_analyst;

-- @as tut_ann
-- @why A DENY beats every GRANT, at every level, whatever order they were issued in.
-- @expect error 1142 employees
SELECT * FROM tutorial.employees;

-- Only REVOKE DENY removes a DENY. Plain REVOKE removes grants, not denies.
-- @as root
REVOKE SELECT ON tutorial.employees FROM tut_analyst;
-- @why Plain REVOKE removed only the explicit GRANT. The DENY needs REVOKE DENY, at exactly the same level (table).
REVOKE DENY SELECT ON tutorial.employees FROM tut_analyst;

-- @as tut_ann
-- @why Both the explicit table GRANT and the DENY are gone, but the broad GRANT on tutorial.* still applies.
-- @expect rows 2
SELECT * FROM tutorial.employees;

-- @phase cleanup
-- @as root
DROP DATABASE tutorial;
DROP USER tut_ann@'%';
DROP ROLE tut_analyst;
