-- @title Experiment 4: REVOKE DENY - exact levels, stale denies and what really removes a DENY
-- @goal Find out which statements remove a DENY and which only look as if they should.
-- @goal Check what happens to a DENY when the database it points to is dropped.

-- @phase setup
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_u@'%';
DROP ROLE IF EXISTS exp_r;
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.t (id INT PRIMARY KEY, pub VARCHAR(20));
INSERT INTO exp_lab.t VALUES (1, 'x');
CREATE ROLE exp_r;
CREATE USER exp_u@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT exp_r TO exp_u@'%';
SET DEFAULT ROLE exp_r FOR exp_u@'%';
GRANT SELECT ON exp_lab.t TO exp_r;
DENY SELECT ON exp_lab.t TO exp_r;

-- @phase demo
-- @as exp_u
-- @expect error 1142 t
SELECT * FROM exp_lab.t;

-- ===== Part 1: REVOKE DENY must match the level exactly =====
-- @as dba
-- @why The DENY is on the TABLE. Revoking at database level finds nothing to revoke (error 1141).
-- @expect error 1141
REVOKE DENY SELECT ON exp_lab.* FROM exp_r;

-- @why Revoking at column level fails too (error 1147: no such grant on this table).
-- @expect error 1147
REVOKE DENY SELECT (pub) ON exp_lab.t FROM exp_r;

-- @why A different privilege type does not match either.
-- @expect error 1147
REVOKE DENY INSERT ON exp_lab.t FROM exp_r;

-- ===== Part 2: plain REVOKE removes grants, not denies =====
REVOKE SELECT ON exp_lab.t FROM exp_r;

-- @why The explicit GRANT is gone, but the DENY line is still in the role's grants.
-- @expect contains DENY SELECT ON `exp_lab`.`t`
SHOW GRANTS FOR exp_r;

-- ===== Part 3: a table-level REVOKE DENY leaves column-level denies alone =====
DENY SELECT (pub) ON exp_lab.t TO exp_r;
REVOKE DENY SELECT ON exp_lab.t FROM exp_r;

-- @why The table-level DENY is removed, the column-level one stays.
-- @expect contains DENY SELECT (`pub`)
SHOW GRANTS FOR exp_r;

-- ===== Part 4: REVOKE ALL PRIVILEGES, GRANT OPTION clears every DENY at once =====
DENY SELECT ON exp_lab.t TO exp_r;
REVOKE ALL PRIVILEGES, GRANT OPTION FROM exp_r;

-- @why Everything is gone in one statement: the quickest (and the most dangerous) way to clear an account.
-- @expect excludes DENY
SHOW GRANTS FOR exp_r;

-- ===== Part 5: DENYs outlive the database they point to =====
-- @phase setup
-- @as dba
GRANT SELECT ON exp_lab.* TO exp_r;
-- @phase demo
-- @as dba
DENY SELECT ON exp_lab.* TO exp_r;
DROP DATABASE exp_lab;

-- @why LIMITATION: dropping the database does NOT remove its database-level DENY. It is still listed.
-- @expect contains DENY SELECT ON `exp_lab`.*
SHOW GRANTS FOR exp_r;

-- @phase setup
-- @as dba
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.t (id INT PRIMARY KEY, pub VARCHAR(20));
INSERT INTO exp_lab.t VALUES (1, 'x');
GRANT SELECT ON exp_lab.* TO exp_r;

-- @phase demo
-- @as exp_u
-- @why The database was re-created and the role was granted SELECT again - but the old DENY silently applies to the NEW database with the same name.
-- @expect error 1142 t
SELECT * FROM exp_lab.t;

-- @as dba
REVOKE DENY SELECT ON exp_lab.* FROM exp_r;

-- @as exp_u
-- @expect rows 1
SELECT * FROM exp_lab.t;

-- @takeaway REVOKE DENY needs the exact level and privilege of the original DENY; always check the result with SHOW GRANTS.
-- @takeaway Audit for stale DENYs after dropping and re-creating databases: they are not cleaned up automatically.

-- @phase cleanup
-- @as dba
DROP DATABASE exp_lab;
DROP USER exp_u@'%';
DROP ROLE exp_r;
