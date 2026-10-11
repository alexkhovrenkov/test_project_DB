-- @title Example 4: column-level GRANT and DENY
-- @goal Let a user read some columns of a table but not others.
-- @goal Combine a table-wide GRANT with a column DENY, and undo it.
-- Run it with:  python app/sqlrunner.py examples/04_column_privileges.sql

-- @phase setup
DROP DATABASE IF EXISTS tutorial;
DROP USER IF EXISTS tut_ann@'%';
DROP USER IF EXISTS tut_bob@'%';
CREATE DATABASE tutorial;
CREATE TABLE tutorial.employees (id INT PRIMARY KEY, name VARCHAR(40), salary INT);
INSERT INTO tutorial.employees VALUES (1, 'Ann', 5200), (2, 'Bob', 4800);
CREATE USER tut_ann@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
CREATE USER tut_bob@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
-- Ann: only two named columns (a positive column privilege).
GRANT SELECT (id, name) ON tutorial.employees TO tut_ann@'%';
-- Bob: the whole table ...
GRANT SELECT ON tutorial.employees TO tut_bob@'%';
-- ... except the salary column (a column-level DENY).
DENY SELECT (salary) ON tutorial.employees TO tut_bob@'%';

-- @phase demo
-- @as tut_ann
-- @expect rows 2
SELECT id, name FROM tutorial.employees;

-- @why SELECT * needs every column. Ann only holds two, so MariaDB reports a table-level refusal (error 1142).
-- @expect error 1142 employees
SELECT * FROM tutorial.employees;

-- @why Error 1143 = "command denied for COLUMN". Filtering on a forbidden column also reads it, so you cannot guess salaries with WHERE.
-- @expect error 1143 salary
SELECT name FROM tutorial.employees WHERE salary > 5000;

-- @as tut_bob
-- @why Bob has the table-wide GRANT, but the column DENY still removes salary.
-- @expect error 1143 salary
SELECT * FROM tutorial.employees;

-- @expect rows 2
SELECT id, name FROM tutorial.employees;

-- @why The denied column is also hidden from SHOW COLUMNS (id and name remain).
-- @expect rows 2
SHOW COLUMNS FROM tutorial.employees;

-- Undo it. A column DENY must be revoked at column level.
-- @as root
REVOKE DENY SELECT (salary) ON tutorial.employees FROM tut_bob@'%';

-- @as tut_bob
-- @expect rows 2
SELECT * FROM tutorial.employees;

-- @phase cleanup
-- @as root
DROP DATABASE tutorial;
DROP USER tut_ann@'%';
DROP USER tut_bob@'%';
