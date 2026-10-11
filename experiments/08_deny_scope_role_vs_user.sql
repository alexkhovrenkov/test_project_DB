-- @title Experiment 8: where you attach a DENY matters (role vs account vs PUBLIC)
-- @goal Test whether a user can shed a DENY that is attached to a role by switching roles.
-- @goal Compare the three places a DENY can live and which of them the user cannot escape.
-- Scenario: a direct GRANT exists (an administrator's earlier mistake), and the "protection" is a DENY on a role.

-- @phase setup
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_u@'%';
DROP ROLE IF EXISTS exp_r;
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.t (id INT PRIMARY KEY, v VARCHAR(20));
INSERT INTO exp_lab.t VALUES (1, 'sensitive');
CREATE ROLE exp_r;
DENY SELECT ON exp_lab.t TO exp_r;
CREATE USER exp_u@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT exp_r TO exp_u@'%';
SET DEFAULT ROLE exp_r FOR exp_u@'%';
-- The mistake: SELECT was granted to the account itself, outside the role.
GRANT SELECT ON exp_lab.* TO exp_u@'%';

-- @phase demo
-- ===== Option 1: DENY attached to a role =====
-- @as exp_u
-- @why The default role is active, and the DENY inside it beats the direct GRANT.
-- @expect error 1142 t
SELECT * FROM exp_lab.t;

-- @why But a user may deactivate their own role. A role's DENY lives only as long as the role is active ...
SET ROLE NONE;

-- @why ... and the direct GRANT is then the only rule left. THE DENY IS GONE.
-- @expect rows 1
SELECT * FROM exp_lab.t;

-- ===== Option 2: DENY attached to the account =====
-- @as root
DENY SELECT ON exp_lab.t TO exp_u@'%';

-- @as exp_u
-- @why A DENY on the account itself applies whatever role is active, even NONE - and it takes effect immediately, in the open session.
-- @expect error 1142 t
SELECT * FROM exp_lab.t;

-- @as root
REVOKE DENY SELECT ON exp_lab.t FROM exp_u@'%';

-- ===== Option 3: DENY attached to PUBLIC =====
-- @as root
DENY SELECT ON exp_lab.t TO PUBLIC;

-- @as exp_u
-- @expect error 1142 t
SELECT * FROM exp_lab.t;

-- @as root
REVOKE DENY SELECT ON exp_lab.t FROM PUBLIC;

-- @as exp_u
-- @why Control: with every DENY removed, the direct GRANT works again.
-- @expect rows 1
SELECT * FROM exp_lab.t;

-- @takeaway A DENY on a role is a good fit when the role is the ONLY source of the user's privileges (as with professor_role): shedding the role then loses the GRANTs as well.
-- @takeaway When privileges can also reach the user from elsewhere (direct grants, other roles, PUBLIC), attach the DENY to the account or to PUBLIC.

-- @phase cleanup
-- @as root
DROP DATABASE exp_lab;
DROP USER exp_u@'%';
DROP ROLE exp_r;
-- @expect any
REVOKE DENY SELECT ON exp_lab.t FROM PUBLIC;
