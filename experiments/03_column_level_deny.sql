-- @title Experiment 3: column-level DENY - what it blocks, and what it leaks
-- @goal Deny one column of an otherwise readable table and test every way of reaching that column.
-- @goal Check what an unprivileged user can still learn about the denied column (metadata, row count).

-- @phase setup
-- Initial configuration: table t with a secret column; the user may read and write the table, except for column "secret".
DROP DATABASE IF EXISTS exp_lab;
DROP USER IF EXISTS exp_u@'%';
CREATE DATABASE exp_lab;
CREATE TABLE exp_lab.t (id INT PRIMARY KEY, pub VARCHAR(20), secret VARCHAR(20));
INSERT INTO exp_lab.t VALUES (1, 'public-1', 'secret-1');
CREATE USER exp_u@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
GRANT SELECT, INSERT, UPDATE ON exp_lab.t TO exp_u@'%';
DENY SELECT (secret) ON exp_lab.t TO exp_u@'%';
DENY UPDATE (secret) ON exp_lab.t TO exp_u@'%';

-- @phase demo
-- @as exp_u
-- @why Control: the non-secret columns are readable.
-- @expect rows 1
SELECT id, pub FROM exp_lab.t;

-- @why SELECT * expands to include "secret", so the whole statement is refused (1143 = column level).
-- @expect error 1143 secret
SELECT * FROM exp_lab.t;

-- @expect error 1143 secret
SELECT secret FROM exp_lab.t;

-- @why Using the column only in a WHERE clause is still a read of it. Otherwise the answer (row returned or not) would leak the value one guess at a time.
-- @expect error 1143 secret
SELECT id FROM exp_lab.t WHERE secret = 'secret-1';

-- @expect error 1143 secret
SELECT id FROM exp_lab.t ORDER BY secret;

-- @why LIMIT-ing the leak via aggregates does not work either.
-- @expect error 1143 secret
SELECT MAX(secret) FROM exp_lab.t;

-- @why Writing: UPDATE of the denied column is refused ...
-- @expect error 1143 secret
UPDATE exp_lab.t SET secret = 'overwritten' WHERE id = 1;

-- @why ... while UPDATE of other columns works: a DENY removes only what it names.
UPDATE exp_lab.t SET pub = 'public-1b' WHERE id = 1;

-- @why INSERT was granted and only UPDATE(secret)/SELECT(secret) were denied, so the user can still WRITE a value into the column at insert time. A write-only column is not the same as a protected column!
INSERT INTO exp_lab.t (id, pub, secret) VALUES (2, 'public-2', 'planted-by-exp_u');

-- @why Metadata, part 1: the column is STILL listed. SHOW COLUMNS shows every column on which you hold ANY privilege, and INSERT on it was never denied.
-- @expect contains secret
SHOW COLUMNS FROM exp_lab.t;

-- @as root
DENY INSERT (secret) ON exp_lab.t TO exp_u@'%';

-- @as exp_u
-- @why Metadata, part 2: with SELECT, UPDATE and INSERT on the column all denied, no privilege is left and the column disappears from SHOW COLUMNS ...
-- @expect excludes secret
SHOW COLUMNS FROM exp_lab.t;

-- @expect excludes secret
SELECT column_name FROM information_schema.columns WHERE table_schema = 'exp_lab' AND table_name = 't';

-- @why ... and the planted-value trick no longer works.
-- @expect error 1143 secret
INSERT INTO exp_lab.t (id, pub, secret) VALUES (3, 'public-3', 'planted-again');

-- @why LIMITATION: SHOW CREATE TABLE still prints the complete definition, including the denied column's name and type (documented by MariaDB).
-- @expect contains secret
SHOW CREATE TABLE exp_lab.t;

-- @why Counting rows needs no column, so it is allowed: the existence and number of rows is not protected by a column DENY.
-- @expect rows 1
SELECT COUNT(*) FROM exp_lab.t;

-- @takeaway A column DENY blocks reading the column in any clause (SELECT list, WHERE, ORDER BY, aggregates).
-- @takeaway It does not hide the column's name (SHOW CREATE TABLE) or the table's row count, and the column stays listed - and writable at INSERT - until every privilege on it is denied.

-- @phase cleanup
-- @as root
DROP DATABASE exp_lab;
DROP USER exp_u@'%';
