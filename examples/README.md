# SQL tutorial

Five short, runnable lessons. Each `.sql` file is ordinary SQL plus a few comment
lines the runner understands (`-- @as`, `-- @expect`, `-- @why`, ...; the full list is at the top of
[app/sqlrunner.py](../app/sqlrunner.py)). Every statement really runs on the MariaDB 13.1 server,
**as the user named by the last `-- @as` line**, over a verified TLS connection. `dba` is the run's
short-lived administrator (see section 8 of the main README); the demo accounts get random in-memory passwords.
For every step you see the SQL, what the file expected, what MariaDB answered, and PASS or FAIL.

| File | You learn |
|---|---|
| [01_roles_and_grants.sql](01_roles_and_grants.sql) | Create a role, `GRANT` to it, give it to a user; default deny |
| [02_deny.sql](02_deny.sql) | `DENY`, testing a denied operation, GRANT cannot undo it, `REVOKE DENY` |
| [03_role_inheritance.sql](03_role_inheritance.sql) | Roles granted to roles, `SET ROLE`, `SET ROLE NONE` |
| [04_column_privileges.sql](04_column_privileges.sql) | Column-level `GRANT` and `DENY` |
| [05_ed25519_authentication.sql](05_ed25519_authentication.sql) | ED25519 accounts and every way a login can fail |

```bash
make examples                                          # all five
.venv/bin/python app/sqlrunner.py examples/02_deny.sql # one lesson
```

**Using your own client instead:** the runner is a convenience; the SQL is plain. To follow a lesson by
hand, open one session per identity and paste the statements for that identity:

```bash
# for the "-- @as dba" steps: root, through the container socket - no password (unix_socket)
make shell
# as a user the lesson creates, e.g. tut_ann: replace '{{pw}}' in its CREATE USER by a password of your
# choice (12+ characters with upper and lower case, a digit and a symbol), then
docker exec -it university-db mariadb -u tut_ann -p
```

The lessons only touch a scratch database called `tutorial` and accounts starting with `tut_`; each
file removes everything it created, so they are safe to run repeatedly.
