-- 05_password_policy.sql
-- Password VALIDATION plugins: every password set from now on (CREATE USER,
-- ALTER USER, SET PASSWORD - also for ed25519 accounts) must pass them.
--   simple_password_check: length (12, set in docker-compose.yml), upper and
--                          lower case, a digit and a special character.
--   password_reuse_check:  refuses a password the same account used within
--                          password_reuse_check_interval days (365).
-- With a validation plugin present, strict_password_validation (ON by default)
-- also refuses passwords given as a pre-computed hash/public key, because the
-- plugin could not check those. See experiments/12_password_policy.sql.
--
-- This runs after 04_users.sql on purpose: the demo accounts are created
-- there with an unusable public key, which strict validation would refuse.
INSTALL SONAME 'simple_password_check';
INSTALL SONAME 'password_reuse_check';
