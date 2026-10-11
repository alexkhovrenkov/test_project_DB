A project for area 5, "Authentication and access control" for the [MariaDB student database projects, 2026-09](https://mariadb.org/bachelor_hackathon_2026-09/).

# Protecting a University Database with MariaDB 13.1: Roles, DENY, ED25519 and Verified TLS

**Constructor University** · **Repository:** <https://github.com/alexkhovrenkov/test_project_DB> · **Branch:** `main`
**MariaDB version:** 13.1.2 (`13.1.2-MariaDB-ubu2604`), Docker image `quay.io/mariadb-foundation/mariadb-devel:13.1`
(the exact build verified is pinned by digest in [.github/workflows/ci.yml](.github/workflows/ci.yml))

```bash
git clone https://github.com/alexkhovrenkov/test_project_DB.git && cd test_project_DB
make demo      # creates certificates, starts MariaDB 13.1, runs every demonstration (no password to configure)
make test      # 117 integration tests against the real server
```

## Contents

1. [Overview and objectives](#1-overview-and-objectives)
2. [Why MariaDB, and why 13.1](#2-why-mariadb-and-why-131)
3. [Requirements and quick start](#3-requirements-and-quick-start)
4. [Scenario, schema and design decisions](#4-scenario-schema-and-design-decisions)
5. [Architecture](#5-architecture)
6. [Roles and permissions](#6-roles-and-permissions)
7. [DENY explained](#7-deny-explained)
8. [Authentication: ED25519](#8-authentication-ed25519)
9. [TLS that is verified, not assumed](#9-tls-that-is-verified-not-assumed)
10. [Security experiments (advanced)](#10-security-experiments-advanced)
11. [Findings: limits and surprises of MariaDB access control](#11-findings-limits-and-surprises-of-mariadb-access-control)
12. [Which control stops which attack](#12-which-control-stops-which-attack)
13. [Test results](#13-test-results)
14. [Reproducing everything](#14-reproducing-everything)
15. [Security hardening and what is still unprotected](#15-security-hardening-and-what-is-still-unprotected)
16. [Troubleshooting](#16-troubleshooting)
17. [Repository layout](#17-repository-layout)
18. [Team](#18-team)
19. [References](#19-references)

---

## 1. Overview and objectives

This repository is a **hands-on, executable tutorial** for MariaDB's security features. It builds a small
fictional university database that holds things worth protecting (grades, bank details) and then:

* controls who may do what with **roles**, **`GRANT`** and the new **`DENY`** statement (MariaDB 13.1),
* stores **no password in any file**: root authenticates with **`unix_socket`** (only via `docker exec`),
  people log in with **ED25519** and type their password, automated runs use passwords that live only in
  memory, and the run's administrator additionally needs a **client certificate** (`REQUIRE X509`),
* forces every network connection through **TLS** and **verifies** the server certificate *and* host name,
* **attacks** every one of those controls and shows which MariaDB mechanism stopped which attack,
* **probes the edges**: eleven experiments on conflicting permissions, role inheritance, views, metadata
  leaks, pattern names and administrative mistakes - some of which found behaviour that is not obvious
  from the documentation (section 11).

The Python code is deliberately small: it sends SQL to MariaDB and prints MariaDB's answer. **All security
decisions are made by MariaDB.** There is no `if user == "professor"` anywhere in this repository.

How this maps to the Area 5 brief ("roles and DENY rather than per-user grants, a named authentication
method instead of a password in a config file, verified TLS, then attack the setup"):

| Brief | Where it is done and shown |
|---|---|
| Roles and `DENY` doing the work | [sql/03_roles.sql](sql/03_roles.sql); sections 6-7; experiments 1, 2, 8 |
| Authentication method instead of a stored password | `unix_socket` for root, ED25519 (+ X509 for the harness), no password on disk: [sql/04_users.sql](sql/04_users.sql), [sql/06_lockdown.sh](sql/06_lockdown.sh), [app/admin.py](app/admin.py); section 8 |
| An attack against each control | section 12; [experiments/](experiments/); [tests/](tests/) |
| TLS verified rather than assumed, and shown to be | section 9; [tests/test_tls.py](tests/test_tls.py) |
| Reproducible from the README on a fresh server | `make demo`; section 3; verified from a clean copy (section 13) |
| Which control stops which attack, what remains unprotected | sections 12 and 15 |

## 2. Why MariaDB, and why 13.1

The project is about MariaDB's own access-control engine; a Python app is only the client. What is
MariaDB-specific here:

| Capability | Why it needs MariaDB |
|---|---|
| **`DENY` / `REVOKE DENY`** (negative grants) | New in **MariaDB 13.1** ([MDEV-14443](https://jira.mariadb.org/browse/MDEV-14443)). MySQL 8 and PostgreSQL have no equivalent: there, "everything except this table" means listing every allowed table and remembering every new one. Older MariaDB rejects the statement. |
| **`ed25519` authentication plugin** (`IDENTIFIED VIA ed25519`) | Ships with MariaDB (`auth_ed25519`); the server stores only a *public key*. MySQL has no such plugin. |
| **`unix_socket` authentication** | The operating-system user *is* the credential: `root@localhost` has no password at all and can only be used inside the container. Default plugin for root in MariaDB packages since 10.4. |
| **MariaDB role model** (`CREATE ROLE`, `SET DEFAULT ROLE`, one active role at a time, roles inside roles) | Differs from MySQL 8 roles and from PostgreSQL's `INHERIT` roles; experiments 2 and 8 depend on these exact semantics. |
| **Privileges as JSON in `mysql.global_priv`** | DENYs are stored in the `denies` key (section 7); `FLUSH PRIVILEGES` rebuilds the role graph (experiment 2). |
| `ACCOUNT LOCK`, `PASSWORD EXPIRE`, `require_secure_transport`, `tls_version`, `PUBLIC` pseudo-role | Used in the authentication and TLS tests. |

**How DENY changes the security model.** Classic SQL access control is *additive*: the user can do
whatever the union of all their grants allows, so a later GRANT can only widen access. With DENY the model
has a **ceiling**: `GRANT SELECT ON university.*` + `DENY SELECT ON university.financial_records` is a
complete, auditable sentence. No later, broader or narrower GRANT can lift the ceiling; only an explicit
`REVOKE DENY` can. That makes the rule "professors never read bank details" robust against future
administrative mistakes (experiment 1) - with caveats we measured (section 11).

**Why ED25519 and unix_socket, and no password file.** With `mysql_native_password` the server stores a
SHA-1-derived hash that is *password-equivalent*: anyone who steals `mysql.user` can authenticate. With
ED25519 the server stores only a public key; the client proves knowledge of the password by signing a random
challenge, and the password never crosses the network. Our test uses the stored value as a password and is
rejected (section 8). ED25519 works with a plain `pip install` of PyMySQL, unlike PARSEC (needs the C
connector). For the one account that never needs the network - root - `unix_socket` is better still: there
is no password to steal at all. Together they remove the classic weak point the area brief names, a
password sitting in a configuration file: nothing in this repository or on disk holds one (section 8).

**What verified TLS protects against.** *Encryption* stops eavesdropping. *Verification* (certificate chain
+ host name) stops an **impostor server**: without it, a perfectly encrypted connection can end at an
attacker. PyMySQL 1.2's default (no TLS options) is encryption **without** verification; section 9 demonstrates the difference with a test.

**How they interact.** TLS protects the *channel and the server's identity*, ED25519 (plus a client
certificate for the administrator) proves the *client's identity* without exposing a reusable secret, roles+GRANT define *what that identity may do*, DENY caps it.
Each fails differently: a stolen password table (ED25519 helps), a sniffed network (TLS), a mistaken GRANT
(DENY), a user switching roles (section 11, finding 2). No layer replaces another.

## 3. Requirements and quick start

**You need:** Docker with the Compose plugin (Docker Desktop on macOS/Windows), Python 3.10 or newer (tested with 3.13), `make`,
`openssl`, `bash`. On Windows use WSL. Developed and verified on macOS (Apple silicon) with Docker 29,
the pinned image was additionally run on x86_64 (emulated).

```bash
git clone https://github.com/alexkhovrenkov/test_project_DB.git
cd test_project_DB
make demo
```

`make demo` is safe to repeat and asks for nothing: there is no password to configure. It will, in order:
generate a CA, a server certificate and a client certificate with owner-only key files
([scripts/generate_certs.sh](scripts/generate_certs.sh)), start MariaDB 13.1 with TLS required
(`docker compose up -d --wait`; on the first start `sql/` creates schema, data, roles and *locked* users and
switches root to `unix_socket`), create a Python virtual environment, create a short-lived administrator
that gives the demo accounts random in-memory passwords ([app/admin.py](app/admin.py)), and run (1) the role demo, (2) the 5 tutorial examples, (3) the 11 experiments (about 2,000 lines of output, saved from a real run in [docs/demo-output.txt](docs/demo-output.txt)).
Every step prints `PASS`/`FAIL`; any failure makes `make` exit non-zero.

| Command | Does |
|---|---|
| `make demo` | everything above |
| `make test` | start the server if needed, run the 117-test pytest suite |
| `make roles` / `make examples` / `make experiments` | one part of the demo |
| `make set-password USER=smith_professor` | choose a password for a demo account (typed, never stored) and unlock it |
| `make sql USER=smith_professor` | `mariadb` client as that account (asks for the password) |
| `make shell` | `mariadb` client as root, through the container socket - no password |
| `python app/menu.py` (after `make set-password`) | interactive menu: log in as any role and try actions |
| `make down` / `make reset` / `make clean` | stop / stop and delete data / also delete certs and venv |

Check the server version:
```bash
docker exec university-db mariadbd --version
# mariadbd  Ver 13.1.2-MariaDB-ubu2604 for debian-linux-gnu on aarch64 (mariadb.org binary distribution)
```

## 4. Scenario, schema and design decisions

A small university keeps four kinds of information in one database, `university`. Four kinds of people use it
(all names and data are made up):

| Person | MariaDB account | Role |
|---|---|---|
| Alice, a student | `alice_student` | `student_role` |
| Prof. Smith | `smith_professor` | `professor_role` |
| Mr. Jones, finance office | `jones_finance` | `finance_role` |
| The database administrator | `uni_admin` | `admin_role` |

```
 students                     courses
 ─────────────────            ─────────────────
 student_id  PK  ◄──┐  ┌────► course_id   PK
 first_name         │  │      code, title, credits, professor
 last_name          │  │
 email              │  │      financial_records
 program            │  │      ─────────────────
 db_username UNIQUE │  │      record_id   PK
                    │  │      student_id  FK ──► students
 grades             │  │      tuition_due, amount_paid
 ─────────────────  │  │      scholarship
 grade_id    PK     │  │      bank_iban   (fake)
 student_id  FK ────┤  │
 course_id   FK ────┼──┘      my_grades (VIEW): one student's own rows
 grade  DECIMAL(2,1)         (rows where students.db_username = the connected user)
```

Files: [sql/01_schema.sql](sql/01_schema.sql), [sql/02_data.sql](sql/02_data.sql). Design decisions:

* **Tables differ in sensitivity on purpose**: `courses` is public catalogue data, `students` is personal
  data, `grades` is *read by many but written by few*, `financial_records` is the crown jewel. That gives
  the access-control model something real to separate (read-only vs read-write, row-level vs table-level).
* **`students.db_username`** links a person to a MariaDB account, so the `my_grades` view can filter by
  `USER()`. This is MariaDB doing row-level security with a view, not Python code.
* **Foreign keys** keep the data honest (MariaDB refuses a grade for a missing student, error 1452).
* **`grade DECIMAL(2,1)`** (German 1.0-5.0 scale) so a column-level privilege on `grade` is meaningful:
  a professor may change *the grade* but not *whose grade it is* (`student_id`).
* **`my_grades` is defined by a dedicated account**, `my_grades_owner`: `ACCOUNT LOCK`, host `localhost`
  only, `SELECT` on three tables. A definer view lends the definer's rights to every reader (experiment 9),
  so the definer is as small as possible instead of `root`.

## 5. Architecture

```
  python app/demo.py ─┐
  python app/menu.py ─┼──►  app/database.py ══ TLS 1.2/1.3, server cert verified ══►  MariaDB 13.1 (Docker)
  pytest (tests/)    ─┤     (ED25519 login,                                        ├─ require_secure_transport=ON
  app/sqlrunner.py ───┘      ssl_verify_cert + identity)                           ├─ roles / GRANT / DENY decide every query
         ▲                                                                          └─ mysql.global_priv holds the rules
  examples/*.sql, experiments/*.sql  (annotated SQL; each step states what MariaDB must answer)
```

* [app/database.py](app/database.py) opens connections: ED25519 login, TLS with `ssl_verify_cert=True` and
  `ssl_verify_identity=True`. **No permission logic.** Values reach SQL only as `%s` parameters.
* [app/actions.py](app/actions.py) holds the university SQL (fixed strings) and the validated `update_grade`.
* [app/demo.py](app/demo.py) runs the same six actions as each role and prints expected / actual / PASS-FAIL.
  Its policy table is a *checklist for verification*; it enforces nothing.
* [app/sqlrunner.py](app/sqlrunner.py) executes the annotated `.sql` tutorial files as the user named in each
  step and compares the result with the file's stated expectation. The SQL files are the experiments;
  pytest runs them too, so documentation cannot drift from reality.
* [docker-compose.yml](docker-compose.yml) starts MariaDB with TLS; the port is published on `127.0.0.1` only.

## 6. Roles and permissions

A **role** is a named bundle of privileges: privileges go to the role once and the role is granted to
users. A new professor needs one statement, `GRANT professor_role TO new_professor`. Without roles the
privileges get copied per person and drift apart.

What each role may do ([sql/03_roles.sql](sql/03_roles.sql); every cell is checked by `make roles` and
`tests/test_permissions.py::test_role_matrix`, 24 combinations):

| Role | `courses` | `students` | `grades` | `my_grades` view | `financial_records` |
|---|---|---|---|---|---|
| `student_role` | Read | No | No | Read (own rows only) | No |
| `professor_role` | Read | Read | Read + update the **`grade` column only** | Read | **DENIED** |
| `finance_role` | No | Read | No | No | Read / insert / update |
| `admin_role` | All | All | All | All | All - but only inside `university.*` |

```sql
CREATE ROLE professor_role;
GRANT professor_role TO 'smith_professor'@'%';             -- give the role to a user
SET DEFAULT ROLE professor_role FOR 'smith_professor'@'%'; -- activate it at every login
```
Without `SET DEFAULT ROLE` the user *holds* the role but it is *inactive* until they run `SET ROLE ...`
(a classic misconfiguration, reproduced in experiment 7).

`GRANT` adds a positive privilege on the server (`*.*`), a database, a table or a single column.
MariaDB's base rule: **anything not granted is forbidden** (shown in [example 1](examples/01_roles_and_grants.sql)).

## 7. DENY explained

**The problem:** the professor should read "everything except financial records". With `GRANT` alone you
list `students`, `courses` and `grades` separately and must remember every future table. Granting
`university.*` would expose the bank details.

**The MariaDB 13.1 solution:** grant broadly, then subtract.

```sql
GRANT SELECT ON university.* TO professor_role;                  -- "read everything..."
DENY  SELECT ON university.financial_records TO professor_role;  -- "...except this table"
```

Rules, from the [official reference](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/deny)
and **each one reproduced on 13.1.2** by an experiment or test:

| Rule | Verified by |
|---|---|
| A DENY beats every GRANT at every level, whatever the order of the statements | experiment 1 (cases A-E), `test_deny_semantics.py` |
| A deny propagates downward: database ▸ table ▸ column | experiment 1 (C, D) |
| A DENY removes only the privilege it names | experiment 1 (E) |
| Only `REVOKE DENY` at the **exact** level removes it (errors 1141 / 1147 otherwise) | experiment 4 |
| Plain `REVOKE` removes grants, not denies | experiment 4 |
| DENY works on roles, accounts and `PUBLIC` (even against the administrator) | experiments 1, 7, 8 |
| A denied table disappears from `SHOW TABLES` / `information_schema` | [example 2](examples/02_deny.sql), experiment 10 |
| DENY lines are shown in `SHOW GRANTS` only to accounts that can read `mysql.*` | experiment 10, `test_permissions.py` |
| Stored in the `denies` key of `mysql.global_priv` | `test_deny_is_stored_in_global_priv_as_json` |
| Routine denies need the type (`ON PROCEDURE` / `ON FUNCTION`; without it: error 1144), block `CALL`/function calls with 1370, hide the routine from `INFORMATION_SCHEMA.ROUTINES`, and disappear when the routine is dropped | experiment 13, `test_routine_deny_*` |

Real `SHOW GRANTS` as an administrator (`make shell`):
```
MariaDB> SHOW GRANTS FOR professor_role;
GRANT USAGE ON *.* TO `professor_role`
GRANT SELECT ON `university`.* TO `professor_role`
GRANT UPDATE (`grade`) ON `university`.`grades` TO `professor_role`
DENY SELECT ON `university`.`financial_records` TO `professor_role`
```

Try it yourself - choose a password for the professor, then log in with it:
```bash
make set-password USER=smith_professor   # asks for the new password twice
make sql USER=smith_professor            # = docker exec -it university-db mariadb -u smith_professor -p university
```
```sql
SELECT code, title FROM courses;       -- works
SELECT * FROM financial_records;
-- ERROR 1142 (42000): SELECT command denied to user 'smith_professor'@'localhost' for table `university`.`financial_records`
```

The official documentation, and the MariaDB article announcing the feature, also warn that DENY is *not a
substitute for least-privilege design*: use it for clear exceptions, as here. Section 11 shows where the
exception mechanism itself has sharp edges.

## 8. Authentication: no password in any file

Authentication answers **"who are you?"**; roles and grants answer **"what may you do?"**. The area brief asks
for "one of the authentication methods in place of a password in a configuration file". This project stores
**no account password anywhere** - not in Git, not in `.env`, not in the container environment, not in the
data directory - and every account still has a real authentication method:

| Account | Authentication | Where its secret lives |
|---|---|---|
| `root@localhost` (no `root@'%'` exists) | **`unix_socket`**: the OS user `root` inside the container | nowhere - there is no password. Use `make shell` / `docker exec … mariadb`. |
| `alice_student`, `smith_professor`, `jones_finance`, `uni_admin` | **ED25519** | created `ACCOUNT LOCK` with an unusable key; a person sets a password with `make set-password` (getpass) and types it at login, or an automated run sets a random one that exists only in that process's memory |
| `harness_<hex>` - the administrator of one test/demo run | **ED25519 + `REQUIRE X509`** | random password in process memory only, plus `certs/client-key.pem` (issued by the project CA); dropped at the end of the run |
| `my_grades_owner@localhost` (view definer) | none - `ACCOUNT LOCK`, cannot log in | - |

| Method named in the brief | Used for |
|---|---|
| **Unix socket** ✅ | root. No password at all; only usable inside the container. Not suitable for the application, which connects over the network (TLS would be pointless over a local socket). |
| **ED25519** ✅ | every network account. Ships with MariaDB, works with `pip install pymysql[ed25519]`, works over TLS. |
| **PARSEC** | not used: the pure-Python PyMySQL cannot speak it (it needs a locally compiled C connector). |

**How it is built** ([sql/04_users.sql](sql/04_users.sql), [sql/06_lockdown.sh](sql/06_lockdown.sh),
[app/admin.py](app/admin.py)):

1. The container starts with `MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1` and `MARIADB_ROOT_HOST=localhost`: the
   image creates only `root@localhost`, reachable only through the socket of the temporary init server
   (`--skip-networking`). We chose this over `MARIADB_RANDOM_ROOT_PASSWORD`, which would print a password into
   the container log.
2. `04_users.sql` creates the demo accounts with `IDENTIFIED VIA ed25519 USING '<public key>' ACCOUNT LOCK`.
   The public key belongs to 32 random bytes that were discarded after computing it, so no password matches.
3. The last init script switches root to `IDENTIFIED VIA unix_socket` and removes the image's `healthcheck`
   accounts together with the file holding their password (`/var/lib/mysql/.my-healthcheck.cnf`);
   `healthcheck.sh` then connects as the OS user root through the socket. We checked the container still
   becomes healthy, also after a restart that keeps the data.
4. Each automated run creates `harness_<hex>` through `docker exec` (socket root) with a random password and
   `REQUIRE X509`, grants it only data, account and grant privileges (no `FILE`, `SUPER`, `SHUTDOWN`,
   `PROCESS`, replication or connection admin), sets random passwords for the demo accounts and unlocks them,
   and drops itself at the end.

*How passwords reach SQL.* MariaDB accepts only a string **literal** inside `PASSWORD(...)`: we checked that a
server-side placeholder (`PASSWORD(?)`) and a variable (`PASSWORD(@pw)`) are both syntax errors (1064). So a
password always travels as an escaped literal. Over a driver connection that is PyMySQL's `%s` parameter;
through `docker exec` (where there is no driver connection) `app/admin.py` uses the same escaping function as
the driver, `pymysql.converters.escape_item`, and sends the SQL on stdin, never on a command line.

Real output (`make set-password`, then logging in through the container socket):
```
$ make set-password USER=smith_professor
New password for smith_professor:
Repeat it:
Password set and account unlocked. Log in with: make sql USER=smith_professor

$ docker exec -i university-db mariadb -u smith_professor -p… university -e "SELECT CURRENT_USER(); SELECT * FROM financial_records;"
CURRENT_USER()
smith_professor@%
ERROR 1142 (42000) at line 1: SELECT command denied to user 'smith_professor'@'localhost' for table `university`.`financial_records`
```

### Password policy: validation and reuse plugins

[sql/05_password_policy.sql](sql/05_password_policy.sql) installs **`simple_password_check`** (configured in
[docker-compose.yml](docker-compose.yml): at least 12 characters, upper and lower case, a digit, a special
character) and **`password_reuse_check`** (`password_reuse_check_interval=365` days). `cracklib_password_check`
is not shipped in the image (we listed `/usr/lib/mysql/plugin`). We checked on the live server that validation
applies to `IDENTIFIED VIA ed25519 USING PASSWORD(...)` and to `SET PASSWORD` for ed25519 accounts, and that
`strict_password_validation` (ON by default) matters: it refuses credentials given as a ready-made public key
(error 1290), which the plugins could not check. The random passwords of the harness and the demo runs always
contain all character classes (`strong_password()` in [app/database.py](app/database.py)).
[experiments/12_password_policy.sql](experiments/12_password_policy.sql) and
[tests/test_password_policy.py](tests/test_password_policy.py) show it; real excerpt:

```
Step 10  user: dba (harness_fcbbec84)  (active role: none)
    SQL      ALTER USER exp_pw_{{run}}@'%' IDENTIFIED VIA ed25519 USING PASSWORD('{{pw}}');
    Expected error 1396
    Actual   error 1396: Operation ALTER USER failed for 'exp_pw_0e6664'@'%'
    Result   PASS
Step 11  user: dba (harness_fcbbec84)  (active role: none)
    SQL      SHOW WARNINGS;
    Actual   ok (3 rows)
             | Warning  1819  password_reuse_check: The password was already used
             | Error    1819  Your password does not satisfy the current policy requirements (password_reuse_check)
             | Error    1396  Operation ALTER USER failed for 'exp_pw_0e6664'@'%'
```

| Attempt (as the administrator) | Result |
|---|---|
| `abc`, `password12345`, `PASSWORD-12345`, `Password-short` | refused, **1819** (`simple_password_check`) |
| `IDENTIFIED VIA ed25519` without a password (= empty password) | refused, **1819** |
| a pre-computed ed25519 public key (`USING '<key>'`) | refused, **1290** (`strict_password_validation`) |
| the same password again with `SET PASSWORD` | refused, **1819** (`password_reuse_check`) |
| the same password again with `ALTER USER` | refused, but as **1396**; the reason is only in `SHOW WARNINGS` (finding 10) |
| the same password for a *different* account; a password containing the account name | **accepted** (finding 11) |

**ED25519 login:** the client says who it is; the server sends a random challenge; the client recomputes the
private key from the typed password and *signs* the challenge; the server verifies with the stored public key.
A failure returns `ERROR 1045 Access denied` before any query can run - the same error for a wrong password and
for a non-existent user, so accounts cannot be enumerated.

Attacks and results ([tests/test_authentication.py](tests/test_authentication.py),
[tests/test_account_model.py](tests/test_account_model.py), [example 5](examples/05_ed25519_authentication.sql)):

| Attack / check | Expected | Actual |
|---|---|---|
| All 4 demo accounts use `ed25519` | yes | ✅ |
| Correct password | login, correct user and role | ✅ |
| Wrong password, empty password, another user's password | error **1045** | ✅ |
| Unknown user vs wrong password | identical error (no enumeration) | ✅ |
| Stored `authentication_string` (public key) used as the password | error **1045** | ✅ |
| Password appears in `mysql.user` / `mysql.global_priv` | never | ✅ |
| Locked account (`ACCOUNT LOCK`) with the correct password | error **4151** | ✅ |
| Expired password | login ok, every statement fails with **1820** | ✅ |
| root over the network (TLS), with an empty, guessed or any password | error **1045** - `root@'%'` does not exist | ✅ |
| root through `docker exec` | `root@localhost`, plugin `unix_socket`, no password | ✅ |
| Harness account with the right password but **without** its client certificate | error **1045** | ✅ |
| Any live password (harness + 4 demo accounts) in any file of the project directory, `.env` included | none | ✅ |
| Password variables in the container environment / healthcheck password file in the data directory | only `MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1` / file absent | ✅ |
| Harness password in the server log | absent | ✅ |

## 9. TLS that is verified, not assumed

TLS does two separate jobs: **encryption** (nobody on the network reads queries and results) and **server
authentication** (the client checks it reached *our* server). A client that encrypts but does not verify
ends up with an encrypted connection *to the attacker*. **PyMySQL 1.2's default is exactly that**: with no TLS options it
switches to "preferred" mode - TLS, but `verify_mode=CERT_NONE` and `check_hostname=False`
(`test_pymysql_default_encrypts_but_does_not_verify` asserts this on the live connection).

[scripts/generate_certs.sh](scripts/generate_certs.sh) creates our own CA, a server certificate for the name
`localhost` signed by it, and a second *unrelated* CA used only to simulate a client that trusts the wrong
authority. Server side ([docker-compose.yml](docker-compose.yml)):
`--ssl-cert/--ssl-key/--ssl-ca`, `--tls-version=TLSv1.2,TLSv1.3`, `--require-secure-transport=ON`.
Client side ([app/database.py](app/database.py)): `ssl_ca=certs/ca.pem`, `ssl_verify_cert=True`, `ssl_verify_identity=True`.

| Attempt ([tests/test_tls.py](tests/test_tls.py)) | Who refuses | Real result |
|---|---|---|
| Correct CA, full verification | - | ✅ connected, `TLSv1.3`, `TLS_AES_256_GCM_SHA384` |
| Client trusts a different CA | client | ❌ `[SSL: CERTIFICATE_VERIFY_FAILED] ... self-signed certificate in certificate chain` |
| Connect to `127.0.0.1` (certificate says `localhost`) | client | ❌ `CERTIFICATE_VERIFY_FAILED ... IP address mismatch` |
| No TLS at all (demo user *and* the administrator) | **server** | ❌ `3159 Connections using insecure transport are prohibited while --require_secure_transport=ON` |
| Server offers only TLS 1.2/1.3; refuses plaintext | server config | ✅ `tls_version=TLSv1.2,TLSv1.3`, `require_secure_transport=ON` |
| Encryption with verification turned **off** (explicitly, or PyMySQL's default) | - | ⚠️ connects. This is "assumed, not verified" - the lesson |

**The private key is not world-readable.** `scripts/generate_certs.sh` writes every key with mode `600`
(`umask 077`, checked after creation). The MariaDB process runs as the unprivileged `mysql` user, so the
container's entrypoint wrapper copies the key into the container with owner `mysql`, mode `600`:
```
$ docker exec university-db ls -l /etc/mysql/tls
-rw-r--r-- 1 mysql mysql 1139 ca.pem
-rw-r--r-- 1 mysql mysql 1131 server-cert.pem
-rw------- 1 mysql mysql 1704 server-key.pem
```
`tests/test_repository_security.py` fails if any `certs/*-key.pem` is group/other-accessible.

## 10. Security experiments (advanced)

Every experiment is an annotated SQL file. Each step is run **as the named user**, over verified TLS, and
printed with SQL, expected result, actual result and PASS/FAIL, plus a "Why" explanation and a security
takeaway. Initial configuration is the visible `[setup]` block at the top of each run. Each file removes
everything it created and touches only scratch objects (`exp_*`, `tut_*`), apart from the read-only
experiments 6 and 10 which attack the real university database.

Sample of the real output (experiment 9, trimmed):
```
Step 3  user: exp_viewer  (active role: none)
    SQL      SELECT * FROM exp_lab.v_definer;
    Expected rows 1
    Actual   ok (1 rows)
             | 1  base-row
    Result   PASS
    Why      FINDING: the DENY on the viewer does NOT block the DEFINER view. The view runs with its definer's privileges, so the same rows are reachable.
```

| # | File | Question | Result (13.1.2) |
|---|---|---|---|
| 1 | [grant_deny_conflicts](experiments/01_grant_deny_conflicts.sql) | Who wins when GRANT and DENY disagree: same level, different levels, either order? | DENY always; db▸table▸column masking; only the named privilege is removed |
| 2 | [multi_role_inheritance](experiments/02_multi_role_inheritance.sql) | GRANT in one branch, DENY three roles deep in another | DENY wins - **but only after `FLUSH PRIVILEGES`** (finding 1) |
| 3 | [column_level_deny](experiments/03_column_level_deny.sql) | Every way to reach a denied column | Blocked in SELECT/WHERE/ORDER BY/aggregates/UPDATE; name still leaks (finding 4) |
| 4 | [revoke_deny](experiments/04_revoke_deny.sql) | What really removes a DENY? | Exact level only; plain REVOKE does not; `REVOKE ALL` does; DENY outlives `DROP DATABASE` (finding 7) |
| 5 | [privilege_escalation](experiments/05_privilege_escalation.sql) | 15 escalation attempts incl. a delegated admin with GRANT OPTION | All refused with specific codes (1959, 1142, 1227, 1044) |
| 6 | [unauthorized_access](experiments/06_unauthorized_access.sql) | Joins, subqueries, other schemas, view widening - on the real DB | Every route to forbidden data blocked |
| 7 | [misconfiguration_recovery](experiments/07_misconfiguration_recovery.sql) | Missing default role, over-broad GRANT, `DENY ... TO PUBLIC` | Symptoms, diagnosis and repair of each; PUBLIC DENY locks out the administrator until revoked |
| 8 | [deny_scope_role_vs_user](experiments/08_deny_scope_role_vs_user.sql) | Can a user shed a role-attached DENY? | **Yes, with `SET ROLE NONE`**; account-level and PUBLIC denies cannot be shed (finding 2) |
| 9 | [views_and_deny](experiments/09_views_and_deny.sql) | DENY vs `SQL SECURITY DEFINER` / `INVOKER` views | DENY on the viewer does not follow a definer view (finding 3) |
| 10 | [metadata_visibility](experiments/10_metadata_visibility.sql) | What can a denied user still learn? | Listings hidden; error codes leak existence (finding 5) |
| 11 | [database_name_patterns](experiments/11_database_name_patterns.sql) | `_`/`%` wildcards in GRANT and DENY | Unescaped `_` leaks a grant; pattern DENY ignored (finding 6) |
| 12 | [password_policy](experiments/12_password_policy.sql) | Do the validation and reuse plugins guard ED25519 accounts? What gets through? | Weak and reused passwords refused (1819/1396/1290); refused passwords recorded, history outlives `DROP USER`, shared passwords allowed (findings 9-11) |
| 13 | [routine_deny](experiments/13_routine_deny.sql) | `DENY EXECUTE ON PROCEDURE/FUNCTION` inside a schema-wide `GRANT EXECUTE` | Calls refused (1370), routine hidden from `INFORMATION_SCHEMA.ROUTINES`, type required (1144), `DROP` removes the deny and re-creating does not restore it |

And five standalone tutorial lessons in [examples/](examples/) (roles, DENY, inheritance, column privileges,
ED25519 failures) - see [examples/README.md](examples/README.md) for how to follow them with any SQL client.

Run them:
```bash
make experiments                                       # all 11
.venv/bin/python app/sqlrunner.py experiments/08_deny_scope_role_vs_user.sql   # one
.venv/bin/python app/sqlrunner.py --quiet experiments/ # only PASS/FAIL lines
```
Complete output of a clean run: [docs/demo-output.txt](docs/demo-output.txt).

## 11. Findings: limits and surprises of MariaDB access control

Everything here was observed on **13.1.2** (a preview release - behaviour may change; the CI "canary" job
re-runs the tests weekly against the floating `13.1` tag to notice). Each finding is reproduced by an
experiment *and* asserted by a test.

1. **A DENY on an inherited role is not enforced until the role graph is rebuilt (fail-open window).**
   After `DENY SELECT ON t TO role_c`, where `role_c` is granted to `role_b`, granted to the role the user
   has active, the user kept reading `t` - even in a brand-new session - until `FLUSH PRIVILEGES` (or any
   later role `GRANT` that rebuilds the graph). A DENY on the *active* role or on the *account* took effect
   at once, even in an open session; so did `REVOKE DENY`, `GRANT` and `REVOKE` on nested roles. This
   qualifies the documentation's statement that a deny on any held role beats a grant on any other role
   at any depth: that holds only once the role graph has been rebuilt. *Implication:* after denying a role that other roles
   inherit, run `FLUSH PRIVILEGES` and **test**. (experiment 2, `test_deny_in_a_nested_role_...`)
   We have not reported this upstream; it is worth a [MariaDB Jira](https://jira.mariadb.org) ticket.
2. **A DENY attached to a role vanishes when the user runs `SET ROLE NONE`** if some other privilege
   (a direct grant, another role) still allows the access. A DENY on the *account* or on `PUBLIC` cannot be
   shed. *Implication:* anchor DENYs to the account when privileges can arrive by several paths.
   `professor_role` is safe because it is the *only* source of the professor's privileges. (experiment 8)
3. **A DENY on a user does not follow a `SQL SECURITY DEFINER` view.** The viewer, denied the base table,
   still reads it through the view, because the view runs with the definer's rights. Conversely a DENY on
   the *definer* breaks the view for everybody (error 1356). `SQL SECURITY INVOKER` views obey the viewer's
   DENY. The reliable cut-off is to DENY (or not grant) the *view*. (experiment 9)
4. **Column DENY hides data, not existence.** `SHOW CREATE TABLE` still prints the denied column's name and
   type; `SHOW COLUMNS` keeps listing it while any other privilege on it (e.g. INSERT) remains; the user can
   still insert into it; `COUNT(*)` works. Reading it in `WHERE`/`ORDER BY`/aggregates *is* blocked.
   (experiment 3)
5. **Error codes reveal that a denied table exists.** `SELECT` on a denied table → `1142`, on a
   non-existent one → `1146`, although `SHOW TABLES` and `information_schema` hide the denied one.
   *Implication:* table names are not secrets. (experiment 10)
6. **Database names in GRANT/DENY are patterns.** `GRANT SELECT ON exp_lab_a.*` also grants `exp1lab1a`
   (each `_` is a wildcard); escape as `` `exp\_lab\_a` ``. A DENY written as a pattern is ignored when a
   more specific (exact) entry exists, so the broad DENY silently does nothing. (experiment 11)
7. **DENYs outlive what they point to.** `DROP DATABASE` leaves a database-level DENY; a re-created database
   with the same name is silently denied again. (experiment 4)
8. **`DENY ... TO PUBLIC` applies to root too.** Existing sessions keep working; new ones are denied. Root
   can recover with `REVOKE DENY ... FROM PUBLIC` (experiment 7). The documentation warns that denying
   `UPDATE` on `mysql.global_priv` to PUBLIC removes even that recovery path (restart with
   `--skip-grant-tables` required). **That hard lockout is not reproduced here** - it needs a disposable
   server restart - so it rests on the documentation only.

9. **The password reuse history keeps refused passwords and outlives the account.** A password that fails
   `simple_password_check` is still written to `mysql.password_reuse_check_history`: the second attempt with
   the same weak password is reported as *reused*. After `DROP USER`, re-creating the account with its old
   password is refused as reused. The history is never cleaned for dropped accounts. The plugin documentation
   does not mention either behaviour. (experiment 12, `test_a_refused_password_is_still_recorded_as_used`,
   `test_reuse_history_survives_drop_user`)
10. **The same policy violation has two error codes.** Reuse through `SET PASSWORD` is error 1819; through
    `ALTER USER ... IDENTIFIED VIA ed25519 USING PASSWORD(...)` it is the generic **1396** "Operation ALTER USER
    failed", with the 1819 only in `SHOW WARNINGS`. Code that looks for 1819 misses it. (experiment 12)
11. **What the password policy does not catch:** two accounts sharing a password (reuse is per account), a
    password containing the account name, and credentials that existed before the plugins were installed
    (the policy never re-checks them: `my_grades_owner` and the image's `mariadb.sys` keep an empty password -
    both are locked, which is why locking matters). (experiment 12)

Routine-level DENY (experiment 13) behaved exactly as documented. Real excerpt:
```
Step 7  user: exp_u  (active role: none)
    SQL      SELECT exp_lab.salary_of(1);
    Expected error 1370 salary_of
    Actual   error 1370: execute command denied to user 'exp_u'@'%' for routine 'exp_lab.salary_of'
    Result   PASS
```
Note the contrast with finding 7: a routine's DENY is removed by `DROP FUNCTION`/`DROP PROCEDURE` (so a
re-created routine is open again), while a database-level DENY survives `DROP DATABASE`.

Other results worth knowing: a delegated administrator with `GRANT OPTION` cannot hand out, or unlock for
themselves, a privilege they are DENIED (experiment 5); `SELECT *` with only some column grants fails at
table level (1142), referencing a denied column fails at column level (1143); `LOAD_FILE` without the FILE
privilege silently returns `NULL` instead of an error.

## 12. Which control stops which attack

| Attack | Stopped by | Evidence | Real error |
|---|---|---|---|
| Stranger guesses a password | ED25519 login | [test_authentication.py](tests/test_authentication.py) | 1045 |
| Attacker steals `mysql.user` and replays the stored value | ED25519 stores a public key only | `test_stolen_authentication_string...` | 1045 |
| Account enumeration through error messages | identical error for unknown user / wrong password | `test_unknown_user_and_wrong_password_look_identical` | 1045 |
| Eavesdropping on the connection | TLS | `test_verified_connection_uses_modern_tls` | - |
| Impostor server with its own certificate | CA verification | `test_client_trusting_a_different_ca...` | client: `CERTIFICATE_VERIFY_FAILED` |
| Traffic redirected to the wrong host name | host-name verification | `test_host_name_mismatch_is_refused` | client: `IP address mismatch` |
| Client talking without TLS (also the administrator) | `require_secure_transport` | `test_plaintext_connection_...` | 3159 |
| Student reads grades / finance data | role has no GRANT | `test_role_matrix` | 1142 |
| Student widens the `my_grades` view | filter is inside the view | `test_student_cannot_widen_the_view` | still 2 rows |
| Professor reads bank details (also via JOIN) | **DENY** | `test_professor_join_cannot_reach_the_denied_table` | 1142 |
| Admin "fixes" it with a later GRANT | **DENY beats GRANT** | `test_deny_beats_a_later_table_level_grant` | 1142 |
| Professor reassigns a grade to another student | column-level GRANT | `test_professor_can_change_the_grade_column_only` | 1143 |
| User activates a role they were never given | role grants | experiment 5 | 1959 |
| User grants themselves access / grants to PUBLIC | GRANT OPTION rules | experiment 5 | 1142 |
| Delegated admin unlocks their own DENY | DENY needs the privilege to lift | experiment 5 | 1142 |
| Create accounts, read `mysql.*`, change root's password | global privileges absent | experiments 5, 6 | 1227 / 1142 / 1044 |
| User calls a stored procedure/function inside a schema they may execute | routine-level DENY | `test_routine_deny_beats_database_grant_execute` | 1370 |
| Weak password set for an account | `simple_password_check` | `test_weak_passwords_are_refused` | 1819 |
| Old password set again | `password_reuse_check` | `test_reuse_is_refused_by_set_password_with_1819` | 1819 / 1396 |
| Bypass the policy with a pre-computed key | `strict_password_validation` | `test_precomputed_public_key_is_refused...` | 1290 |
| Locked / expired account | `ACCOUNT LOCK`, `PASSWORD EXPIRE` | `test_locked_account...`, `test_expired_password...` | 4151 / 1820 |
| SQL injection through the app | parameters + input validation | `test_update_grade_rejects_injection_payloads` | ValueError / no match |

**Not protected** - see also section 15: a legitimate reader copying data (finance can copy every IBAN);
anyone with root; the server host or Docker daemon; weak passwords; a compromised client machine;
the metadata leaks of section 11; and a role-attached DENY next to a second source of the same privilege.

## 13. Test results

All numbers are from actual runs on 2026-10-11 against `13.1.2-MariaDB-ubu2604` (arm64 and x86_64).

| Command | Result |
|---|---|
| `make demo`, from a clean copy of the repository (no `.env`, certs or venv; native arm64) | exit 0 - role demo **24/24** actions as expected; tutorial examples **108/108** steps; experiments **325/325** steps; 0 FAIL |
| `make demo` a second time on the same server | exit 0, identical totals (idempotent) |
| `make test` (pytest, real server, same clean copy) | **117 passed** in ~1 s ([docs/test-output.txt](docs/test-output.txt)) |
| pinned image as **x86_64** (emulated on Apple silicon): `make test` and `make demo` | 117 passed; role demo 24/24; examples 108/108; experiments 325/325 |
| `shellcheck` on `scripts/*.sh`, `sql/*.sh` (official Docker image) | no findings |

Test files ([tests/](tests/)), all connecting to the real server:

| File | Covers |
|---|---|
| [test_permissions.py](tests/test_permissions.py) | the 4×6 role matrix with exact error codes, view isolation, column privilege, DENY beats later GRANT, SHOW GRANTS/SHOW TABLES visibility, JSON storage, injection payloads |
| [test_deny_semantics.py](tests/test_deny_semantics.py) | GRANT/DENY conflicts (levels, order), nested roles, column-level DENY, `REVOKE DENY` (exact level, plain REVOKE, REVOKE ALL), SET ROLE NONE, definer views, wildcard names, stale denies, PUBLIC lockout and recovery |
| [test_authentication.py](tests/test_authentication.py) | ED25519 for all accounts, wrong/empty/foreign passwords, no enumeration, stolen public key, no clear-text password, lock and expiry |
| [test_tls.py](tests/test_tls.py) | verified connection and protocol version, wrong CA, host-name mismatch, plaintext refused (demo user and administrator), verification-off lesson, PyMySQL's unverified default |
| [test_experiments.py](tests/test_experiments.py) | runs all 16 `.sql` tutorial files; any mismatching step fails with the step-by-step output |
| [test_repository_security.py](tests/test_repository_security.py) | key files owner-only, no secrets/keys tracked, `.env` and keys ignored, no interpolated password in SQL/shell, no string-built SQL in `app/`, TLS verification on, port on loopback |

Tests use random throw-away names (`t_lab_<hex>`) and clean up; after a run the server is as `sql/` left it.

**Do the tests actually test?** Mutation checks, run for real: with the professor's DENY revoked
(`REVOKE DENY SELECT ON university.financial_records FROM professor_role`) **8 tests failed**
(`test_role_matrix[professor-financial]`, `test_deny_beats_a_later_table_level_grant`, the JOIN test, the
`SHOW TABLES` test, the SHOW GRANTS visibility test, the `mysql.global_priv` JSON test, and experiments 6
and 10); restoring it gave 115/115 again (the suite had 115 tests at that point).
With `certs/server-key.pem` set to mode 644 the key-permission test failed; `make certs` repaired it.

**Continuous integration:** [.github/workflows/ci.yml](.github/workflows/ci.yml) installs dependencies,
runs `shellcheck`, starts the same Docker image (TLS and ED25519 included - GitHub-hosted runners have
Docker and quay.io is public, so **nothing is skipped or mocked**), runs `make test` and `make demo`, and
fails on any failing test. Job `test` pins the image digest; job `canary` uses the floating tag and may fail
without failing the workflow. *The workflow file is validated (YAML parses, the commands it runs were run
locally including on x86_64), but it has not yet been executed on GitHub - that requires pushing this branch.*

## 14. Reproducing everything

| To reproduce | Command | Look for |
|---|---|---|
| The whole project from nothing | `make clean && make demo` | exit 0; last line before the closing message: `TOTAL: 325 steps passed, 0 failed` (experiments) |
| Role matrix (section 6) | `make roles` | `Role demo: 24/24 actions behaved as expected.` |
| Tutorial (section 10) | `make examples` | `TOTAL: 108 steps passed, 0 failed` |
| All experiments / one experiment | `make experiments` / `.venv/bin/python app/sqlrunner.py experiments/08_*.sql` | `... N passed, 0 failed` |
| ED25519 attacks (section 8) | `.venv/bin/python -m pytest tests/test_authentication.py -v` | all PASSED |
| TLS attacks (section 9) | `.venv/bin/python -m pytest tests/test_tls.py -v` | all PASSED |
| DENY semantics (section 7) | `.venv/bin/python -m pytest tests/test_deny_semantics.py -v` | all PASSED |
| Everything, verbosely | `.venv/bin/python -m pytest -v` | 117 passed |
| Password-free account model (section 8) | `.venv/bin/python -m pytest tests/test_account_model.py -v` | all PASSED |
| By hand, as a role | `make set-password USER=smith_professor`, then `make sql USER=smith_professor` | section 7 |
| Interactively | `make set-password USER=…`, then `.venv/bin/python app/menu.py` | pick a role, type its password, try all actions |

## 15. Security hardening and what is still unprotected

**Done in this repository** (and checked by tests where marked 🧪):

* 🧪 TLS private keys are mode `600` on the host and inside the container (earlier versions used `644`).
* 🧪 No account password in any file (section 8): root is `unix_socket`-only, the demo accounts start locked,
  automated runs keep their passwords in memory, people type theirs; `.env` holds only non-secret settings.
* 🧪 No `root@'%'`: root cannot be reached over the network at all.
* 🧪 The administrator of a run is a short-lived, least-privilege account that also needs a client
  certificate (`REQUIRE X509`).
* 🧪 No password is interpolated into SQL text: driver parameters, or the driver's escaping function on stdin.
* 🧪 SQL injection: the app passes values only as parameters (and validates numbers); a test fails if `app/`
  builds SQL by string formatting. Test fixtures build only identifiers they generated themselves.
* 🧪 Verified TLS everywhere (`ssl_verify_cert`, `ssl_verify_identity`); `tls_version` limited to 1.2/1.3;
  `require_secure_transport=ON`.
* 🧪 The database port is published on `127.0.0.1` only, not on the network.
* `my_grades` runs as a locked, localhost-only, three-table read-only definer instead of root.
* The admin role is limited to `university.*` (no `mysql.*`, no account management).
* No debug flags are enabled; nothing sensitive is logged (the runner prints `{{pw}}`, not the value).

**Still unprotected / limitations** - honest list:

* **Anyone who can run `docker exec` on this machine is root in the database** (that is what `unix_socket`
  means here). Access to the Docker daemon must be protected like the root password it replaces.
* The harness's client key (`certs/client-key.pem`) is a long-lived file credential. It is not sufficient on its
  own (the account also needs its in-memory password and exists only during a run), but it is a secret on
  disk, protected only by file permissions (`600`).
* During the few seconds of first initialisation root has an empty password, reachable only through the socket
  of the temporary server (no networking). If initialisation failed before `06_lockdown.sh`, the container
  would be left in that state; `make reset` starts over.
* A password typed into `make set-password` / `make sql` is visible to that terminal session's process memory,
  as with any client.
* The CA key lives on the same machine as the server, certificates are valid for 365 days and there is no
  revocation.
* TLS protects data in transit only; it does not help against the server host, Docker daemon, a compromised
  client, or database files at rest (no encryption at rest here).
* Roles and DENY do not restrict root; anyone who can become root (here: `docker exec`) can `REVOKE DENY`.
* Permissions cannot tell legitimate access from misuse: finance can copy every IBAN it may read.
* The password policy does not stop two accounts sharing a password, a password containing the account name, or
  credentials that existed before the plugins were installed (finding 11).
* `MariaDB 13.1` is a **preview** release; the findings in section 11 (especially finding 1) may change.
  The Docker tag floats; pin `MARIADB_IMAGE` to a digest for exact reproducibility.
* The documented hard lockout (PUBLIC DENY on `mysql.global_priv`) is not reproduced.
* `make` is required (use WSL on Windows). The `university-db` container name is fixed, so two copies of the
  project cannot run at the same time.

## 16. Troubleshooting

| Problem | Fix |
|---|---|
| `make: docker: command not found` / daemon not running | Start Docker Desktop; verify with `docker info`. |
| `The container name "/university-db" is already in use` | Another copy of this project is running: `docker compose down` there (or `docker rm -f university-db`). |
| `port is already allocated` | Another MariaDB/MySQL uses 3306. Set `MARIADB_PORT=3307` in `.env`. |
| `ERROR 1045` / `4151 account is locked` when you log in by hand | The demo accounts start locked and every `make demo`/`make test` gives them new random passwords: run `make set-password USER=…` again. |
| Container exits at start, log mentions `server-key.pem` | Certificates are missing/unreadable: `make reset`, `rm -rf certs`, `make up`. |
| `no password known for …` | Automated tools set passwords themselves; for interactive tools run `make set-password USER=…` first and use a terminal (the password is asked for with getpass). |
| `CERTIFICATE_VERIFY_FAILED` when you connect with your own client | Pass `--ssl-ca=certs/ca.pem --ssl-verify-server-cert` and connect to `localhost` (the certificate name). |
| `ModuleNotFoundError: nacl` / auth plugin error | Use the project venv: `make venv`; ED25519 needs `pymysql[ed25519]`. |
| A test says `DENY on an inherited role is now enforced immediately` | The server's behaviour changed (finding 1): update section 11 and experiment 2. |
| An experiment was interrupted and left objects | Re-run it; every file starts by dropping its own leftovers. `make reset` always restores a pristine server. |
| `06_lockdown.sh: Permission denied` in `docker logs university-db` | `chmod +x sql/06_lockdown.sh`, then `make reset && make demo`. |

## 17. Repository layout

```
├── README.md                    this document
├── Makefile                     make demo | test | roles | examples | experiments | set-password | sql | shell | down | reset | clean
├── docker-compose.yml           MariaDB 13.1 with TLS; key copied in with owner-only permissions
├── .env.example                 optional non-secret settings (port, container name, image) - no passwords
├── requirements.txt             pymysql[ed25519], python-dotenv        requirements-dev.txt  + pytest
├── .github/workflows/ci.yml     CI: shellcheck, MariaDB 13.1 container, pytest, demo
├── sql/                         run by the image on first start, in this order:
│   ├── 01_schema.sql            tables
│   ├── 02_data.sql              fake data
│   ├── 03_roles.sql             roles, GRANT, DENY, the my_grades view and its definer
│   ├── 04_users.sql             ED25519 users, created LOCKED with an unusable key (no password)
│   ├── 05_password_policy.sql   simple_password_check + password_reuse_check
│   └── 06_lockdown.sh           root -> unix_socket; removes the image's healthcheck password file
├── scripts/
│   └── generate_certs.sh        CA, server and client certificates, keys mode 600
├── app/
│   ├── database.py              verified-TLS connections; passwords from memory or getpass. No security logic.
│   ├── admin.py                 socket-root helper, the short-lived harness account, set-password
│   ├── actions.py               the university SQL (fixed strings) + validated update_grade
│   ├── demo.py                  six actions x four roles, expected/actual/PASS-FAIL
│   ├── menu.py                  interactive version
│   └── sqlrunner.py             runs annotated .sql files as different users
├── examples/                    5 standalone SQL lessons (+ README on using your own client)
├── experiments/                 11 advanced security experiments
├── tests/                       pytest suite against the real server (117 tests)
└── docs/
    ├── demo-output.txt          complete output of one clean `make demo`
    └── test-output.txt          output of `pytest -v` from the same clean run
```

## 18. Team

**Not supplied.** The repository does not record the team members, and none have been invented. Please fill in:

| Name | Role in the project |
|---|---|
| _(name - to be supplied)_ | _(e.g. schema and roles / authentication and TLS / experiments / tests and CI / documentation)_ |
| _(name - to be supplied)_ | _(...)_ |

The Git history currently shows a single "first commit" by `Julymichy.14`; contributions per member cannot be
derived from it.

## 19. References

Official MariaDB documentation:

* [DENY and REVOKE DENY](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/deny) (reference: syntax, precedence, metadata effects, limitations)
* [MariaDB 13.1 Feature in Focus: DENY / Negative Grants](https://mariadb.org/mariadb-13-1-feature-in-focus-deny-negative-grants/) · [MDEV-14443](https://jira.mariadb.org/browse/MDEV-14443)
* [MariaDB 13.1 Changes & Improvements](https://mariadb.com/docs/release-notes/community-server/13.1/mariadb-13.1-changes-and-improvements)
* [GRANT](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/grant) · [REVOKE](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/revoke) · [SHOW GRANTS](https://mariadb.com/docs/server/reference/sql-statements/administrative-sql-statements/show/show-grants)
* [mysql.global_priv table](https://mariadb.com/docs/server/reference/system-tables/the-mysql-database-tables/mysql-global_priv-table)
* [Roles Overview](https://mariadb.com/docs/server/security/user-account-management/roles/roles_overview) · [CREATE ROLE](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/create-role)
* [Password Validation Plugins](https://mariadb.com/docs/server/reference/plugins/password-validation-plugins) · [simple_password_check](https://mariadb.com/docs/server/reference/plugins/password-validation-plugins/simple-password-check-plugin) · [password_reuse_check](https://mariadb.com/docs/server/reference/plugins/password-validation-plugins/password-reuse-check-plugin)
* [Authentication Plugin - Unix Socket](https://mariadb.com/docs/server/reference/plugins/authentication-plugins/authentication-plugin-unix-socket)
* [Authentication Plugins](https://mariadb.com/docs/server/reference/plugins/authentication-plugins) · [ed25519](https://mariadb.com/docs/server/reference/plugins/authentication-plugins/authentication-plugin-ed25519) · [PARSEC](https://mariadb.com/docs/server/reference/plugins/authentication-plugins/authentication-plugin-parsec)
* [Secure Connections Overview](https://mariadb.com/docs/server/security/encryption/data-in-transit-encryption/secure-connections-overview) · [Enabling TLS on MariaDB Server](https://mariadb.com/docs/server/security/encryption/data-in-transit-encryption/data-in-transit-encryption-enabling-tls-on-mariadb-server) · [Securing Connections for Client and Server](https://mariadb.com/docs/server/security/encryption/data-in-transit-encryption/securing-connections-for-client-and-server)

Other: [PyMySQL](https://github.com/PyMySQL/PyMySQL) (client), [pytest](https://docs.pytest.org/), the
[assignment page](https://mariadb.org/bachelor_hackathon_2026-09/) (Area 5 requirements and rubric).
