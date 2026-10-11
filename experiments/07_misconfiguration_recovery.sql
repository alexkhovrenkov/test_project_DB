-- @title Experiment 7: administrative misconfigurations and how to recover
-- @goal Make three typical administration mistakes on purpose, observe the symptoms, and repair each one.
-- Mistakes: (1) a role granted but never made default, (2) an over-broad GRANT, (3) a DENY on PUBLIC.

-- @phase setup
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_u@'%';
DROP ROLE IF EXISTS exp_r;
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.pub_t    (id INT PRIMARY KEY, v VARCHAR(20));
CREATE TABLE exp_lab.secret_t (id INT PRIMARY KEY, v VARCHAR(20));
INSERT INTO exp_lab.pub_t    VALUES (1, 'public');
INSERT INTO exp_lab.secret_t VALUES (1, 'top-secret');
CREATE ROLE exp_r;
GRANT SELECT ON exp_lab.pub_t TO exp_r;
CREATE USER exp_u@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');

-- @phase demo
-- ===== Mistake 1: the role is granted, but SET DEFAULT ROLE is forgotten =====
-- @as dba
GRANT exp_r TO exp_u@'%';

-- @as exp_u
-- @why Symptom: "I was given the role but I get permission errors". The role is held but inactive.
-- @expect error 1142 pub_t
SELECT * FROM exp_lab.pub_t;

-- @as dba
-- @why Diagnosis: SHOW GRANTS lists the role, but there is no SET DEFAULT ROLE line.
-- @expect excludes SET DEFAULT ROLE
SHOW GRANTS FOR exp_u@'%';

SET DEFAULT ROLE exp_r FOR exp_u@'%';

-- @reconnect
-- @as exp_u
-- @why Repair: the default role applies at the next login (the user may also just run SET ROLE exp_r).
-- @expect rows 1
SELECT * FROM exp_lab.pub_t;

-- ===== Mistake 2: GRANT ALL on the whole database instead of one table =====
-- @as dba
GRANT ALL PRIVILEGES ON exp_lab.* TO exp_r;

-- @as exp_u
-- @why Symptom: nothing fails - that is the danger. The user can now read (and change) the secret table.
-- @expect rows 1
SELECT * FROM exp_lab.secret_t;

-- @as dba
-- @why Detection: audit the grants from the privilege tables. information_schema.schema_privileges lists database-wide grants.
-- @expect contains exp_r
SELECT grantee, table_schema, privilege_type FROM information_schema.schema_privileges WHERE table_schema = 'exp_lab' AND privilege_type = 'SELECT';

-- Repair: revoke the broad privileges, then re-grant only what was intended.
REVOKE ALL PRIVILEGES ON exp_lab.* FROM exp_r;

-- @as exp_u
-- @expect error 1142 secret_t
SELECT * FROM exp_lab.secret_t;

-- ===== Mistake 3: DENY ... TO PUBLIC =====
-- @as dba
-- @why PUBLIC means every account, including the administrator who types it. (Here limited to the scratch database; a global PUBLIC DENY is far worse - see Limitations in the README.)
DENY SELECT ON exp_lab.* TO PUBLIC;

-- @why Privileges of an OPEN session are not recomputed: the administrator (dba) still works in the session that issued the DENY ...
-- @expect rows 1
SELECT * FROM exp_lab.pub_t;

-- @reconnect
-- @why ... but after reconnecting, the administrator is locked out of the data too.
-- @expect error 1142 pub_t
SELECT * FROM exp_lab.pub_t;

-- @why Recovery: the administrator can still lift a PUBLIC deny (the documented exception: REVOKE DENY ... FROM PUBLIC works with UPDATE on mysql.global_priv).
REVOKE DENY SELECT ON exp_lab.* FROM PUBLIC;

-- @reconnect
-- @expect rows 1
SELECT * FROM exp_lab.pub_t;

-- @takeaway Misconfigurations mostly fail silently (mistake 2) or lock people out (1 and 3). SHOW GRANTS and information_schema.*_privileges are the audit tools; REVOKE / REVOKE DENY at the exact level are the repair tools.
-- @takeaway A PUBLIC DENY is the sharpest edge of the feature. The official docs warn that denying UPDATE on mysql.global_priv to PUBLIC removes even the recovery path; that case is NOT reproduced here because recovering needs a server restart with privilege checks disabled.

-- @phase cleanup
-- @as dba
DROP DATABASE exp_lab;
DROP USER exp_u@'%';
DROP ROLE exp_r;
-- @expect any
REVOKE DENY SELECT ON exp_lab.* FROM PUBLIC;
