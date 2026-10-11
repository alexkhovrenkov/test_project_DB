-- @title Experiment 9: DENY and views (SQL SECURITY DEFINER vs INVOKER)
-- @goal Find out whether a DENY on a user also blocks the data that user can reach through a view.
-- @goal Find out what a DENY on the view's DEFINER does to everybody who uses the view.
-- This matters for the project: my_grades is a view over tables the student cannot read.

-- @phase setup
-- exp_definer owns two views over t_base: one SQL SECURITY DEFINER, one SQL SECURITY INVOKER. exp_viewer may only use the views.
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_definer@'%';
DROP USER IF EXISTS exp_viewer@'%';
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.t_base (id INT PRIMARY KEY, v VARCHAR(20));
INSERT INTO exp_lab.t_base VALUES (1, 'base-row');
CREATE USER exp_definer@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
CREATE USER exp_viewer@'%'  IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT SELECT ON exp_lab.t_base TO exp_definer@'%';
CREATE DEFINER = exp_definer@'%' SQL SECURITY DEFINER VIEW exp_lab.v_definer AS SELECT id, v FROM exp_lab.t_base;
CREATE DEFINER = exp_definer@'%' SQL SECURITY INVOKER VIEW exp_lab.v_invoker AS SELECT id, v FROM exp_lab.t_base;
GRANT SELECT ON exp_lab.v_definer TO exp_viewer@'%';
GRANT SELECT ON exp_lab.v_invoker TO exp_viewer@'%';
-- The viewer is explicitly DENIED the base table.
DENY SELECT ON exp_lab.t_base TO exp_viewer@'%';

-- @phase demo
-- @as exp_viewer
-- @why Baseline: the base table is denied.
-- @expect error 1142 t_base
SELECT * FROM exp_lab.t_base;

-- @why FINDING: the DENY on the viewer does NOT block the DEFINER view. The view runs with its definer's privileges, so the same rows are reachable.
-- @expect rows 1
SELECT * FROM exp_lab.v_definer;

-- @why The INVOKER view runs with the viewer's own privileges, so here the DENY applies (reported as error 1356: the view cannot be used).
-- @expect error 1356
SELECT * FROM exp_lab.v_invoker;

-- ===== What a DENY on the definer does =====
-- @as root
DENY SELECT ON exp_lab.t_base TO exp_definer@'%';

-- @as exp_viewer
-- @why A DENY on the view's definer applies even though the viewer holds privileges on the view: the view stops working for everyone who uses it.
-- @expect error 1356
SELECT * FROM exp_lab.v_definer;

-- @as root
REVOKE DENY SELECT ON exp_lab.t_base FROM exp_definer@'%';

-- ===== How to actually cut off a view =====
-- @as root
DENY SELECT ON exp_lab.v_definer TO exp_viewer@'%';

-- @as exp_viewer
-- @why The reliable fix is to DENY (or not grant) the VIEW itself: access to data is controlled at each object, and a view is an object.
-- @expect error 1142 v_definer
SELECT * FROM exp_lab.v_definer;

-- @takeaway A DENY on a base table does not follow data through a SQL SECURITY DEFINER view. Whoever can SELECT the view reads what the definer can read.
-- @takeaway Treat definer views as privilege delegation: grant on them deliberately, and keep the definer's own privileges minimal. The project's my_grades view is defined by a dedicated locked account that can only SELECT three tables (sql/03_roles.sql), not by root.

-- @phase cleanup
-- @as root
DROP DATABASE exp_lab;
DROP USER exp_definer@'%';
DROP USER exp_viewer@'%';
