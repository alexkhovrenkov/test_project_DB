-- @title Experiment 10: what a denied user can still learn (metadata and error codes)
-- @goal Check which metadata channels hide a denied table, and which still reveal that it exists.
-- Uses the real university database: smith_professor is denied financial_records.

-- @phase demo
-- @as smith_professor
-- @why Channel 1: SHOW TABLES hides the denied table.
-- @expect excludes financial_records
SHOW TABLES FROM university;

-- @why Channel 2: so does information_schema.
-- @expect excludes financial_records
SELECT table_name FROM information_schema.tables WHERE table_schema = 'university';

-- @why Channel 3: SHOW COLUMNS, SHOW CREATE TABLE and DESCRIBE are refused.
-- @expect error 1142 financial_records
SHOW CREATE TABLE university.financial_records;

-- @expect error 1142 financial_records
SHOW COLUMNS FROM university.financial_records;

-- @why Channel 4 - A LEAK: reading a denied table gives error 1142 ("command denied") ...
-- @expect error 1142 financial_records
SELECT * FROM university.financial_records;

-- @why ... but reading a table that does not exist gives error 1146 ("doesn't exist"). Comparing the two error codes tells an attacker that financial_records exists, although every listing hides it.
-- @expect error 1146 no_such_table
SELECT * FROM university.no_such_table;

-- @why The professor cannot read their own DENY: SHOW GRANTS lists GRANT lines only (DENY lines need SELECT on the mysql database) ...
-- @expect excludes DENY
SHOW GRANTS;

-- @as root
-- @why ... while the administrator sees the DENY as a separate line, for audits.
-- @expect contains DENY SELECT ON `university`.`financial_records`
SHOW GRANTS FOR professor_role;

-- @takeaway Hiding works for listings (SHOW TABLES, information_schema), but the error codes 1142 vs 1146 still reveal that a denied table exists.
-- @takeaway Names are not secrets: do not rely on a DENY to hide that a table or column exists. Do not put sensitive information in table names.
