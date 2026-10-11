-- @title Experiment 12: password validation and reuse plugins
-- @goal Check that simple_password_check and password_reuse_check (installed by sql/05_password_policy.sql) also guard ED25519 accounts.
-- @goal Record the real error codes, and find what the policy does NOT catch.
-- Configuration (docker-compose.yml): minimal length 12, at least one upper- and lower-case letter, digit and
-- special character; a password counts as "used" for 365 days. strict_password_validation is ON (the default).
-- Account names end in {{run}}, a random suffix per run: the reuse history outlives DROP USER (see below), so
-- re-using the same names would make a second run behave differently.

-- @phase setup
DROP USER IF EXISTS exp_hash@'%';

-- @phase demo
-- @why The policy as the server sees it.
-- @expect rows 3
SHOW VARIABLES WHERE Variable_name IN ('simple_password_check_minimal_length', 'password_reuse_check_interval', 'strict_password_validation');

-- @expect rows 2
SELECT plugin_name, plugin_status FROM information_schema.plugins WHERE plugin_type = 'PASSWORD VALIDATION';

-- ===== Weak passwords =====
-- @why Too short and missing character classes: refused, error 1819. Validation applies to IDENTIFIED VIA ed25519 USING PASSWORD(...) too.
-- @expect error 1819 simple_password_check
CREATE USER exp_weak_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('abc');

-- @why FINDING: the SAME weak password again is now reported as REUSED. The refused password was written to the reuse history anyway, although the account was never created.
-- @expect error 1819 password_reuse_check
CREATE USER exp_weak_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('abc');

-- @why Long enough, but no upper-case letter and no special character.
-- @expect error 1819 simple_password_check
CREATE USER exp_weak_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('password12345');

-- @why IDENTIFIED VIA ed25519 with no USING clause means the EMPTY password - which the policy refuses.
-- @expect error 1819
CREATE USER exp_weak_{{run}}@'%' IDENTIFIED VIA ed25519;

-- @why With a validation plugin installed, strict_password_validation also refuses a credential given as a ready-made public key or hash: the plugin could not check it (1290).
-- @expect error 1290 strict-password-validation
CREATE USER exp_hash@'%' IDENTIFIED VIA ed25519 USING 'lEiAPNNMP1kq0dRsguIBKo/em5EPb9Y0272TblVhRUw';

-- @why A strong password (random for this run) is accepted.
CREATE USER exp_pw_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');

-- @why FINDING: a WEAK password set with ALTER USER is refused too - but reported as the generic 1396, not 1819 ...
-- @expect error 1396
ALTER USER exp_pw_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('Weak-pass');

-- @why ... the reason (simple_password_check) is only in the warnings.
-- @expect contains simple_password_check
SHOW WARNINGS;

-- ===== Reused passwords =====
-- @why Setting the same password again with SET PASSWORD: refused by password_reuse_check, error 1819. The account keeps its ed25519 plugin.
-- @expect error 1819 password_reuse_check
SET PASSWORD FOR exp_pw_{{run}}@'%' = PASSWORD('{{pw}}');

-- @why FINDING: the same reuse through ALTER USER is reported as the generic error 1396 ("Operation ALTER USER failed") ...
-- @expect error 1396
ALTER USER exp_pw_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');

-- @why ... the real reason is only visible in the warnings. Code that checks for 1819 to detect a policy violation would miss it.
-- @expect contains password_reuse_check: The password was already used
SHOW WARNINGS;

-- @why FINDING: the history also outlives the account. Drop it and create it again with its old password: refused as reused.
DROP USER exp_pw_{{run}}@'%';

-- @expect error 1819 password_reuse_check
CREATE USER exp_pw_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');

-- ===== What gets through =====
-- @why FINDING: reuse is checked per account. Another account may use exactly the same password.
CREATE USER exp_pw2_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');

-- @why FINDING: simple_password_check only counts characters; a password that contains the account name passes.
CREATE USER exp_weak_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('exp_weak_{{run}}-Password-1');

-- @why FINDING: the policy only runs when a password is SET. Accounts created before the plugins were installed keep their old credential: here two LOCKED accounts with an empty password (my_grades_owner from sql/03_roles.sql, and the image's mariadb.sys).
-- @expect rows 2
SELECT user, plugin FROM mysql.user WHERE authentication_string = '' AND plugin = 'mysql_native_password' AND user IN ('my_grades_owner', 'mariadb.sys');

-- @takeaway Both plugins guard ED25519 accounts and every way of setting a password (CREATE USER, ALTER USER, SET PASSWORD); strict validation blocks the pre-computed-key loophole.
-- @takeaway They do not re-check existing credentials, do not stop two accounts sharing a password, and do not compare the password with the account name. Lock accounts that must never log in (as this project does).
-- @takeaway The reuse history keeps refused passwords and outlives DROP USER: it grows forever (mysql.password_reuse_check_history) and makes a re-created account inherit the old account's history.

-- @phase cleanup
DROP USER exp_pw2_{{run}}@'%';
DROP USER exp_weak_{{run}}@'%';
