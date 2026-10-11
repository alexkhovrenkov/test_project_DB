-- @title Experiment 2: privileges and denies through several roles
-- @goal Find a MariaDB 13.1.2 limitation: a DENY on an inherited role is not enforced until the role graph is rebuilt.
-- @goal See how privileges flow down a chain of roles, and how a DENY deep in the role graph interacts with a GRANT elsewhere.
-- Role graph built below:    exp_team --> exp_readers   (GRANT SELECT on both tables)
--                            exp_team --> exp_guard --> exp_audit_block   (DENY SELECT on t_audit)
-- The user holds only exp_team, exp_readers (directly) and exp_plain (a separate role with its own GRANT).

-- @phase setup
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_u@'%';
DROP ROLE IF EXISTS exp_team;
DROP ROLE IF EXISTS exp_readers;
DROP ROLE IF EXISTS exp_guard;
DROP ROLE IF EXISTS exp_audit_block;
DROP ROLE IF EXISTS exp_plain;
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.t_data  (id INT PRIMARY KEY, v VARCHAR(20));
CREATE TABLE exp_lab.t_audit (id INT PRIMARY KEY, v VARCHAR(20));
INSERT INTO exp_lab.t_data  VALUES (1, 'data');
INSERT INTO exp_lab.t_audit VALUES (1, 'audit');
CREATE ROLE exp_team;
CREATE ROLE exp_readers;
CREATE ROLE exp_guard;
CREATE ROLE exp_audit_block;
CREATE ROLE exp_plain;
GRANT SELECT ON exp_lab.* TO exp_readers;
GRANT SELECT ON exp_lab.t_audit TO exp_plain;
GRANT exp_readers TO exp_team;
GRANT exp_guard TO exp_team;
GRANT exp_audit_block TO exp_guard;
CREATE USER exp_u@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT exp_team TO exp_u@'%';
GRANT exp_plain TO exp_u@'%';
-- Both roles stay inactive until the user chooses one.

-- @phase demo
-- @as exp_u
-- @why Part 1: GRANT is inherited two levels down (exp_u -> exp_team -> exp_readers). Activate the top role.
SET ROLE exp_team;

-- @expect rows 1
SELECT * FROM exp_lab.t_data;

-- @why No DENY exists yet: t_audit is readable through the inherited GRANT.
-- @expect rows 1
SELECT * FROM exp_lab.t_audit;

-- Now deny t_audit on a role three levels down.
-- @as root
DENY SELECT ON exp_lab.t_audit TO exp_audit_block;

-- @as exp_u
-- @why Part 2 - A FINDING (MariaDB 13.1.2): the DENY exists but is NOT enforced yet. A DENY on a role that is inherited by another role only takes effect after the server rebuilds its role graph. Until then the user is still allowed (fail-open).
-- @expect rows 1
SELECT * FROM exp_lab.t_audit;

-- The documented remedy: make the server rebuild its privilege tables.
-- @as root
FLUSH PRIVILEGES;

-- @as exp_u
-- @why Part 3: now the DENY (in exp_audit_block, a role of a role of a role) beats the GRANT that arrives through a different branch (exp_readers).
-- @expect error 1142 t_audit
SELECT * FROM exp_lab.t_audit;

-- @expect rows 1
SELECT * FROM exp_lab.t_data;

-- @why Part 4: exp_plain is a different role that GRANTs t_audit directly. Switch to it: its graph does not contain the DENY, so access works.
SET ROLE exp_plain;

-- @expect rows 1
SELECT * FROM exp_lab.t_audit;

-- @why A DENY only applies to the roles that are in the ACTIVE role's graph. Cutting a role out of the graph (or never activating it) also cuts out its DENYs.
-- @expect error 1142 t_data
SELECT * FROM exp_lab.t_data;

-- @takeaway Roles compose: a DENY anywhere below the active role beats a GRANT anywhere else below it.
-- @takeaway After DENYing a role that other roles inherit, run FLUSH PRIVILEGES and TEST. A DENY on the account itself, or on the role the user activates, is enforced immediately (experiment 8 shows both).
-- @takeaway MariaDB activates one role at a time (SET ROLE), so a DENY is only as strong as the role graph it belongs to. See experiment 8.

-- @phase cleanup
-- @as root
DROP DATABASE exp_lab;
DROP USER exp_u@'%';
DROP ROLE exp_team;
DROP ROLE exp_readers;
DROP ROLE exp_guard;
DROP ROLE exp_audit_block;
DROP ROLE exp_plain;
