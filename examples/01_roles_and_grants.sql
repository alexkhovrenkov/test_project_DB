-- @title Example 1: roles and GRANT
-- @goal Create a role, give it privileges once, give the role to a user.
-- @goal See that anything you did not GRANT is forbidden (default deny).
-- Everything happens in a scratch database called "tutorial"; the university
-- data is not touched. Run it with:  python app/sqlrunner.py examples/01_roles_and_grants.sql

-- @phase setup
DROP DATABASE IF EXISTS tutorial;
DROP USER IF EXISTS tut_ann@'%';
DROP ROLE IF EXISTS tut_reader;
CREATE DATABASE tutorial;
CREATE TABLE tutorial.projects  (id INT PRIMARY KEY, name VARCHAR(40));
CREATE TABLE tutorial.employees (id INT PRIMARY KEY, name VARCHAR(40), salary INT);
INSERT INTO tutorial.projects  VALUES (1, 'Apollo'), (2, 'Gemini');
INSERT INTO tutorial.employees VALUES (1, 'Ann', 5200), (2, 'Bob', 4800);

-- A role is a named bundle of privileges. Create it, then fill it.
CREATE ROLE tut_reader;
GRANT SELECT ON tutorial.projects TO tut_reader;

-- An account that logs in with ED25519 (password = random value for this run).
CREATE USER tut_ann@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT tut_reader TO tut_ann@'%';
-- Make the role active automatically at login. Without this line the user
-- holds the role but must run SET ROLE tut_reader first.
SET DEFAULT ROLE tut_reader FOR tut_ann@'%';

-- @phase demo
-- @as dba
-- @why SHOW GRANTS FOR a role lists exactly what the role can do.
-- @expect contains SELECT
SHOW GRANTS FOR tut_reader;

-- @as tut_ann
-- @why The role was granted SELECT on projects, so this works.
-- @expect rows 2
SELECT * FROM tutorial.projects;

-- @why Nothing was granted on employees. MariaDB's rule: what is not granted is forbidden.
-- @expect error 1142 employees
SELECT * FROM tutorial.employees;

-- @why Only SELECT was granted, so writing to projects fails as well.
-- @expect error 1142
INSERT INTO tutorial.projects VALUES (3, 'Mercury');

-- Now the administrator extends the ROLE once; every user holding it benefits.
-- @as dba
GRANT INSERT ON tutorial.projects TO tut_reader;

-- @as tut_ann
-- @why Role privileges are looked up on every statement, so no re-login is needed.
INSERT INTO tutorial.projects VALUES (3, 'Mercury');

-- @phase cleanup
-- @as dba
DROP DATABASE tutorial;
DROP USER tut_ann@'%';
DROP ROLE tut_reader;
