# SQL tutorial

## Start here (10 minutes)

1. **Run everything once** (starts MariaDB 13.1, runs every demo; needs Docker, Python 3.10+, `make`):
   ```bash
   make demo
   ```
2. **Give the professor a password** - you choose it; it is set on the server and stored nowhere else
   (at least 12 characters with upper and lower case, a digit and a symbol, or the server refuses it):
   ```bash
   make set-password USER=smith_professor
   ```
3. **Open a client as the professor** (asks for that password):
   ```bash
   make sql USER=smith_professor
   ```
4. **See the DENY at work** - type the two statements from section 7 of the main README:
   ```sql
   SELECT code, title FROM courses;   -- works: GRANT SELECT ON university.* TO professor_role
   SELECT * FROM financial_records;
   -- ERROR 1142 (42000): SELECT command denied to user 'smith_professor'@'localhost' for table `university`.`financial_records`
   ```
   The professor may read the whole database *except* that one table, because of a single
   `DENY SELECT ON university.financial_records TO professor_role`. Type `exit` to leave.
5. **Read how it works, step by step:** [02_deny.sql](02_deny.sql), or run it:
   `.venv/bin/python app/sqlrunner.py examples/02_deny.sql`.

Note: every `make demo` / `make test` gives the demo accounts new random passwords again; repeat step 2 to
log in by hand afterwards.

## The lessons

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
docker compose exec mariadb mariadb -u tut_ann -p
```

The lessons only touch a scratch database called `tutorial` and accounts starting with `tut_`; each
file removes everything it created, so they are safe to run repeatedly.
