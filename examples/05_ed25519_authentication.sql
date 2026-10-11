-- @title Example 5: ED25519 authentication and failed logins
-- @goal Create an account that authenticates with ED25519 instead of a stored password hash.
-- @goal See the different ways a login can fail, and which error code each produces.
-- Run it with:  python app/sqlrunner.py examples/05_ed25519_authentication.sql

-- @phase setup
DROP USER IF EXISTS tut_ann@'%';
CREATE USER tut_ann@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');

-- @phase demo
-- @as root
-- @why MariaDB stored an ed25519 PUBLIC key, not a password hash. We print the plugin name only (never the stored value).
-- @expect contains ed25519
SELECT user, plugin FROM mysql.user WHERE user = 'tut_ann';

-- @why The client proves it knows the password by signing a server challenge; the password is never sent.
-- @login tut_ann

-- @why Wrong password: error 1045 and nothing else. No query can run.
-- @expect error 1045
-- @login tut_ann wrong

-- @why An account that does not exist gives the SAME error 1045, so an attacker cannot tell which accounts exist.
-- @expect error 1045
-- @login nobody_here wrong

-- @as root
ALTER USER tut_ann@'%' ACCOUNT LOCK;

-- @why Even the correct password fails while the account is locked: error 4151.
-- @expect error 4151
-- @login tut_ann

-- @as root
ALTER USER tut_ann@'%' ACCOUNT UNLOCK;
ALTER USER tut_ann@'%' PASSWORD EXPIRE;

-- @as tut_ann
-- @why With an expired password the login succeeds but every statement fails with 1820 until the password is changed.
-- @expect error 1820
SELECT 1;

-- @phase cleanup
-- @as root
DROP USER tut_ann@'%';
