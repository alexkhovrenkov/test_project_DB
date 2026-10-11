-- @title Experiment 13: DENY on stored procedures and functions
-- @goal Block one procedure and one function that a database-level GRANT EXECUTE allows.
-- @goal Check metadata hiding, the routine-type rule, REVOKE DENY, and what DROP does to a routine's DENY.
-- The DENY reference says routine denies must name the routine type (PROCEDURE / FUNCTION), and that dropping
-- the routine removes its deny. This experiment tests both on the real server.

-- @phase setup
-- Initial configuration: three routines; the user may EXECUTE everything in exp_lab.
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_u@'%';
CREATE DATABASE exp_lab;
CREATE PROCEDURE exp_lab.payroll_report() SELECT 'payroll report' AS result;
CREATE FUNCTION exp_lab.salary_of(id INT) RETURNS INT DETERMINISTIC RETURN 5000 + id;
CREATE PROCEDURE exp_lab.public_report() SELECT 'public report' AS result;
CREATE USER exp_u@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT EXECUTE ON exp_lab.* TO exp_u@'%';

-- @phase demo
-- @as exp_u
-- @why Control: the database-level GRANT EXECUTE covers every routine.
-- @expect contains payroll report
CALL exp_lab.payroll_report();

-- @expect contains 5001
SELECT exp_lab.salary_of(1);

-- @as dba
DENY EXECUTE ON PROCEDURE exp_lab.payroll_report TO exp_u@'%';
DENY EXECUTE ON FUNCTION exp_lab.salary_of TO exp_u@'%';

-- @why The DENY lines name the routine type.
-- @expect contains DENY EXECUTE ON PROCEDURE `exp_lab`.`payroll_report`
SHOW GRANTS FOR exp_u@'%';

-- @as exp_u
-- @why The procedure is refused despite the database-level GRANT: error 1370 ("execute command denied ... for routine").
-- @expect error 1370 payroll_report
CALL exp_lab.payroll_report();

-- @expect error 1370 salary_of
SELECT exp_lab.salary_of(1);

-- @why The routine that was not denied still works.
-- @expect contains public report
CALL exp_lab.public_report();

-- @why Metadata: the denied routines disappear from INFORMATION_SCHEMA.ROUTINES; only public_report is listed.
-- @expect rows 1
SELECT routine_name FROM information_schema.routines WHERE routine_schema = 'exp_lab';

-- @as dba
-- @why Without PROCEDURE/FUNCTION the name is read as a TABLE, and EXECUTE is not a table privilege: error 1144.
-- @expect error 1144
DENY EXECUTE ON exp_lab.payroll_report TO exp_u@'%';

-- @why The same rule applies to REVOKE DENY.
-- @expect error 1144
REVOKE DENY EXECUTE ON exp_lab.salary_of FROM exp_u@'%';

-- @why With the type, REVOKE DENY lifts the procedure's deny.
REVOKE DENY EXECUTE ON PROCEDURE exp_lab.payroll_report FROM exp_u@'%';

-- @as exp_u
-- @expect contains payroll report
CALL exp_lab.payroll_report();

-- ===== DROP removes the deny =====
-- @as dba
DROP FUNCTION exp_lab.salary_of;

-- @why The function's DENY is gone together with the function.
-- @expect excludes DENY EXECUTE ON FUNCTION
SHOW GRANTS FOR exp_u@'%';

CREATE FUNCTION exp_lab.salary_of(id INT) RETURNS INT DETERMINISTIC RETURN 5000 + id;

-- @as exp_u
-- @why Re-created under the same name: the deny does NOT come back, the database GRANT applies again. Compare experiment 4: a DATABASE-level deny survives DROP DATABASE.
-- @expect contains 5001
SELECT exp_lab.salary_of(1);

-- @takeaway DENY EXECUTE closes one routine inside a broadly granted schema, and hides it from INFORMATION_SCHEMA.ROUTINES.
-- @takeaway Routine denies are tied to the routine: dropping it removes the deny, so a re-created routine is open again. Re-apply the DENY in the same migration that re-creates the routine.

-- @phase cleanup
-- @as dba
DROP DATABASE exp_lab;
DROP USER exp_u@'%';
