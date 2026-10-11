-- @title Example 3: roles granted to roles (inheritance)
-- @goal Build a hierarchy: editor includes everything reader can do.
-- @goal See that only ONE role is active at a time, and what SET ROLE does.
-- Run it with:  python app/sqlrunner.py examples/03_role_inheritance.sql

-- @phase setup
DROP DATABASE IF EXISTS tutorial;
DROP USER IF EXISTS tut_ann@'%';
DROP ROLE IF EXISTS tut_reader;
DROP ROLE IF EXISTS tut_editor;
CREATE DATABASE tutorial;
CREATE TABLE tutorial.projects (id INT PRIMARY KEY, name VARCHAR(40));
INSERT INTO tutorial.projects VALUES (1, 'Apollo');
CREATE ROLE tut_reader;
CREATE ROLE tut_editor;
GRANT SELECT ON tutorial.projects TO tut_reader;
-- A role can be granted to another role: tut_editor inherits tut_reader.
GRANT tut_reader TO tut_editor;
GRANT INSERT, UPDATE ON tutorial.projects TO tut_editor;
CREATE USER tut_ann@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
-- Ann gets ONLY the editor role; the reader privileges arrive through it.
GRANT tut_editor TO tut_ann@'%';

-- @phase demo
-- @as tut_ann
-- @why No default role was set, so no role is active yet: Ann can do nothing.
-- @expect error 1142
SELECT * FROM tutorial.projects;

-- @why Roles must be activated with SET ROLE (or made default with SET DEFAULT ROLE).
SET ROLE tut_editor;

-- @why SELECT was never granted to tut_editor directly. It is inherited from tut_reader.
-- @expect rows 1
SELECT * FROM tutorial.projects;

-- @why INSERT was granted to tut_editor itself.
INSERT INTO tutorial.projects VALUES (2, 'Gemini');

-- @why SET ROLE NONE switches every role off: all inherited privileges vanish together.
SET ROLE NONE;

-- @expect error 1142
SELECT * FROM tutorial.projects;

-- @why Ann was never granted tut_reader directly, so she cannot activate it: roles are only usable if granted.
-- @expect error 1959
SET ROLE tut_reader;

-- @phase cleanup
-- @as dba
DROP DATABASE tutorial;
DROP USER tut_ann@'%';
DROP ROLE tut_reader;
DROP ROLE tut_editor;
