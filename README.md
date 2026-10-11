A project for area 5, "Authentication and access control" for the [MariaDB student database projects, 2026-09](https://mariadb.org/bachelor_hackathon_2026-09/).

# Protecting a University Database with MariaDB 13.1: Roles, DENY, ED25519 and Verified TLS

**MariaDB version:** 13.1.2 (preview), Docker image `quay.io/mariadb-foundation/mariadb-devel:13.1`

## Contents

1. [Project overview](#1-project-overview)
2. [Why MariaDB 13.1](#2-why-mariadb-131)
3. [Project scenario](#3-project-scenario)
4. [Data model](#4-data-model)
5. [Roles](#5-roles)
6. [GRANT explained](#6-grant-explained)
7. [DENY explained](#7-deny-explained)
8. [Authentication: ED25519](#8-authentication-ed25519)
9. [TLS](#9-tls)
10. [Installation](#10-installation)
11. [Running the demo](#11-running-the-demo)
12. [Running the security tests](#12-running-the-security-tests)
13. [Results](#13-results)
14. [What each control protects](#14-what-each-control-protects)
15. [What these controls do NOT protect against](#15-what-these-controls-do-not-protect-against)
16. [Repository layout](#16-repository-layout)
17. [Team](#17-team)
18. [References](#18-references)

---

## 1. Project overview

This repository is a **hands-on tutorial** for MariaDB's security features. It sets up a tiny
fictional university database that holds things worth protecting (grades, bank details), and then:

* controls who can do what with **roles**, **`GRANT`** and the new **`DENY`** statement,
* logs users in with **ED25519 authentication**,
* forces every network connection to use **TLS**, and **verifies** the server's certificate,
* **attacks** each of those controls and shows exactly which MariaDB feature stops each attack.

The Python part is intentionally small. It only sends SQL to MariaDB and prints what MariaDB answers.
**All security decisions are made by MariaDB itself**, not by Python code. There is no
`if user == "professor": ...` anywhere in this repository.

## 2. Why MariaDB 13.1

`DENY` (sometimes called *negative grants*) was **added in MariaDB 13.1**. It lets you say
"everything in this database **except** this table" in two statements, instead of granting every
allowed table one by one. Neither MySQL nor PostgreSQL has an equivalent. Older MariaDB versions
reject the `DENY` statement, so this project needs 13.1. We use the preview image recommended by
the MariaDB Foundation: `quay.io/mariadb-foundation/mariadb-devel:13.1`.

## 3. Project scenario

A small university keeps four kinds of information in one database, `university`. Four kinds of
people use it:

| Person | MariaDB account | Role |
|---|---|---|
| Alice, a student | `alice_student` | `student_role` |
| Prof. Smith | `smith_professor` | `professor_role` |
| Mr. Jones from the finance office | `jones_finance` | `finance_role` |
| The database administrator | `uni_admin` | `admin_role` |

All names and data are made up.

## 4. Data model

```
 students                     courses
 ─────────────────            ─────────────────
 student_id  PK  ◄──┐  ┌────► course_id   PK
 first_name         │  │      code, title
 last_name          │  │      credits
 email              │  │      professor
 program            │  │
 db_username        │  │
                    │  │
 grades             │  │      financial_records
 ─────────────────  │  │      ─────────────────
 grade_id    PK     │  │      record_id   PK
 student_id  FK ────┤  │      student_id  FK ──► students
 course_id   FK ────┼──┘      tuition_due
 grade              │         amount_paid
                    │         scholarship
                    │         bank_iban   (fake)
 my_grades (VIEW) ──┘ only the logged-in student's rows
```

* **PK (primary key):** uniquely identifies a row.
* **FK (foreign key):** must match a primary key in another table. For example, MariaDB refuses a grade
  for a student who does not exist (`ERROR 1452 ... a foreign key constraint fails`).

Different tables are sensitive in different ways:

| Table | Sensitivity |
|---|---|
| `courses` | Public catalogue information. |
| `students` | Personal contact details. Staff may read them. |
| `grades` | Many people may *read* them, but only professors should *change* them. |
| `financial_records` | **The most sensitive.** Bank account numbers, payment status and scholarships. Only the finance office (and admin) should ever see them. A professor has no reason to know who still owes tuition. |

Files: [sql/01_schema.sql](sql/01_schema.sql) (tables), [sql/02_data.sql](sql/02_data.sql) (fake data).

## 5. Roles

A **role** is a named bundle of privileges. Privileges are given to the role **once**, and the role
is then given to users. When a new professor joins, the administrator runs a single statement,
`GRANT professor_role TO new_professor`. Without roles, every privilege would have to be repeated
for every person, and those copies slowly drift apart over time.

What each role is actually allowed to do (taken from [sql/03_roles.sql](sql/03_roles.sql) and
confirmed by the tests):

| Role | `courses` | `students` | `grades` | `my_grades` view | `financial_records` |
|---|---|---|---|---|---|
| `student_role` | Read | No | No | Read (own rows only) | No |
| `professor_role` | Read | Read | Read + update the `grade` column | Read | **DENIED** |
| `finance_role` | No | Read | No | No | Read / insert / update |
| `admin_role` | All | All | All | All | All |

```sql
CREATE ROLE professor_role;
GRANT professor_role TO 'smith_professor'@'%';             -- give the role to a user
SET DEFAULT ROLE professor_role FOR 'smith_professor'@'%'; -- turn it on at every login
```

Without `SET DEFAULT ROLE`, the user would have the role but it would be *inactive* until they ran
`SET ROLE professor_role;` themselves.

## 6. GRANT explained

`GRANT` adds a **positive privilege**: permission to do one kind of action (`SELECT`, `INSERT`,
`UPDATE`, ...) on one thing. That thing can be the whole server (`*.*`), one database
(`university.*`), one table, or even **one column**.

MariaDB's rule is simple: **anything not granted is forbidden.** That is why the student cannot touch
the `grades` table. We never wrote a rule that blocks them; we just never allowed it.

```sql
-- Professor: read every table in the database (including tables added in the future)
GRANT SELECT ON university.* TO professor_role;

-- Professor: may change the grade column, but not e.g. which student a grade belongs to
GRANT UPDATE (grade) ON university.grades TO professor_role;

-- Student: only the course list and a view of their own grades
GRANT SELECT ON university.courses   TO student_role;
GRANT SELECT ON university.my_grades TO student_role;
```

The `my_grades` view filters with `USER()`, the name of whoever is connected. So Alice gets only
her own grades even though she has no privilege on the `grades` table itself. The view runs with
its creator's privileges.

## 7. DENY explained

**The problem:** the professor should read "everything except financial records". With `GRANT`
alone, you would have to grant `students`, `courses` and `grades` separately, and remember to add
every new table forever. If you grant `university.*` instead, the professor can read the bank
details too.

**The MariaDB 13.1 solution:** grant broadly, then subtract with `DENY`.

```sql
GRANT SELECT ON university.* TO professor_role;                  -- "read everything..."
DENY  SELECT ON university.financial_records TO professor_role;  -- "...except this table"
```

`DENY` adds a **negative privilege**. The rules we verified on MariaDB 13.1.2:

* **DENY beats every GRANT**, at every level, whatever order they were issued in. Our test grants the
  professor role `SELECT` *directly on* `financial_records` after the `DENY`, and access is still refused.
* **Only `REVOKE DENY` removes it.** For example: `REVOKE DENY SELECT ON university.financial_records FROM professor_role;`
* **DENY works on roles**, so it applies to every user who has the role.
* **It is visible to auditors.** Root sees it as its own line in `SHOW GRANTS`:
  ```
  MariaDB> SHOW GRANTS FOR professor_role;
  GRANT USAGE ON *.* TO `professor_role`
  GRANT SELECT ON `university`.* TO `professor_role`
  GRANT UPDATE (`grade`) ON `university`.`grades` TO `professor_role`
  DENY SELECT ON `university`.`financial_records` TO `professor_role`
  ```
  A "missing grant" is invisible, whereas a `DENY` documents the intent.
* **The denied user does not see the DENY line.** When `smith_professor` runs `SHOW GRANTS` they see only
  the GRANT lines, because DENY lines are shown only to accounts that can read the `mysql` system database.
* **SHOW TABLES hides the denied table.** The professor's `SHOW TABLES` lists `courses`, `grades`,
  `my_grades` and `students`, but not `financial_records`.
* Internally, the deny is stored as JSON in `mysql.global_priv`:
  `"denies":[{"type":"table","db":"university","table":"financial_records","bits":1}]`.

**Try it yourself** (after [installation](#10-installation)). This logs in through the server's
local socket inside the container:

```bash
docker exec -it university-db mariadb -u smith_professor -p university
```
Enter the `PROFESSOR_PASSWORD` from your `.env` file, then:
```sql
SELECT code, title FROM courses;      -- works
SELECT * FROM financial_records;
-- ERROR 1142 (42000): SELECT command denied to user 'smith_professor'@'localhost'
--                     for table `university`.`financial_records`
```

## 8. Authentication: ED25519

Authentication answers **"who are you?"**. It is separate from authorization (roles and grants),
which answers **"what may you do?"**.

### Normal password authentication

In classic MySQL/MariaDB (`mysql_native_password`), the server stores a hash of your password. At
login, the client mixes the password with a random challenge from the server. The weakness is that
the stored hash is *password-equivalent*: anyone who steals the `mysql.user` table and captures one
login can impersonate the user. It also uses SHA-1, an old algorithm.

### What we chose: ED25519, and why

Area 5 names three methods. We compared them for this project:

| Method | Verdict for this project |
|---|---|
| **Unix socket** | No password at all; the operating system vouches for the local user. But it only works for programs on the **same machine** as the server. Our Python app connects over the network into Docker, and TLS would be pointless over a local socket. |
| **PARSEC** | The newest method (MariaDB 11.6+). The pure-Python driver PyMySQL does not support it; you would need the C-based connector compiled locally, which is fragile on student laptops. |
| **ED25519** ✅ | Ships with MariaDB and is supported by PyMySQL with a simple `pip install`. Easy to set up, easy to explain, and works over TLS. |

### How ED25519 works

**Setup.** When the account is created:
```sql
INSTALL SONAME 'auth_ed25519';   -- load the plugin once (the server remembers it)
CREATE USER 'smith_professor'@'%' IDENTIFIED VIA ed25519 USING PASSWORD('...');
```
MariaDB turns the password into a **key pair**: a *private key* that can only be recomputed from
the password, and a *public key*. **Only the public key is stored:**
```
user             plugin   authentication_string
smith_professor  ed25519  F1/gEaYhiphyZ3L9gjCmcBrbNFd/7i/vp9c/zZJAZw0
```

**Login:**
1. The client says "I am `smith_professor`".
2. The server sends a random number, the *challenge*.
3. The client recomputes the private key from the typed password and uses it to **sign** the challenge.
4. The server checks the signature with the stored public key. Only someone who knows the password
   can produce a valid signature. The password itself never travels over the network.
5. **If the check fails**, the server closes the connection with
   `ERROR 1045 (28000): Access denied for user ...` before a single query can run. The same error is
   returned for a wrong password and for a user that does not exist, so an attacker cannot use it to
   find out which accounts exist.

All demo accounts **and `root`** use ED25519 (see [sql/04_users.sh](sql/04_users.sh)). Passwords
are never written in the repository. They come from your local `.env` file, which Git ignores.

## 9. TLS

### What TLS is

TLS is the technology behind the padlock in `https://`. Between our client and MariaDB it does two
separate jobs:

1. **Encryption:** nobody on the network can read the traffic. Without it, every query and every
   result (including bank details) crosses the network as plain text.
2. **Server authentication:** the client checks that it is really talking to *our* server.

### Encrypted is not the same as verified

Job 2 is what "TLS verified rather than assumed" means. An attacker who can redirect your
connection can run their *own* server with their *own* certificate. A client that encrypts but does
not check the certificate ends up with a perfectly encrypted connection **to the attacker**.

This is not hypothetical. **PyMySQL's default** (when you pass no TLS options) is to encrypt with
certificate checking turned **off** (`verify_mode=CERT_NONE`, `check_hostname=False`). Our test
suite shows that such a connection succeeds even though the client trusts nothing.

### How the certificate check works

[scripts/generate_certs.sh](scripts/generate_certs.sh) creates:

* **A CA (Certificate Authority):** our own "University Demo CA" (`ca.pem` plus its private key
  `ca-key.pem`). A CA is someone the client trusts to vouch for servers.
* **A server certificate** (`server-cert.pem`): it says "I am `localhost`, and here is my public key",
  and it is **signed by the CA**. The server keeps the matching private key (`server-key.pem`).
* **An unrelated CA** (`untrusted-ca.pem`), used only to simulate a client that trusts the wrong CA.

When connecting, the client (see [app/database.py](app/database.py)) checks two things:
```python
ssl_ca="certs/ca.pem",     # the CA we trust
ssl_verify_cert=True,      # 1. was the server certificate signed by that CA?
ssl_verify_identity=True,  # 2. is the certificate issued for the host we dialed ("localhost")?
```
An impostor cannot get a certificate signed by our CA, because they do not have `ca-key.pem`.

On the server side ([docker-compose.yml](docker-compose.yml)):
```
--ssl-cert=/etc/mysql/certs/server-cert.pem
--ssl-key=/etc/mysql/certs/server-key.pem
--ssl-ca=/etc/mysql/certs/ca.pem
--require-secure-transport=ON     # refuse any network connection without TLS
```

### How we prove verification works

| Attempt | Who refuses | Result |
|---|---|---|
| Correct CA, full verification | — | ✅ connected with `TLSv1.3`, cipher `TLS_AES_256_GCM_SHA384` |
| Client trusts a different CA | client | ❌ `CERTIFICATE_VERIFY_FAILED ... self-signed certificate in certificate chain` |
| Connect to `127.0.0.1` (the certificate only says `localhost`) | client | ❌ `CERTIFICATE_VERIFY_FAILED ... IP address mismatch` |
| No TLS at all | **server** | ❌ `3159 Connections using insecure transport are prohibited while --require_secure_transport=ON` |
| TLS with verification turned off | — | ⚠️ connects. This is "assumed, not verified". |

## 10. Installation

**You need:** Docker (Docker Desktop, or Docker Engine with the Compose plugin), Python 3.9+,
`openssl` and `bash`. On Windows, use WSL or Git Bash for the shell commands.

```bash
# 1. Get the code
git clone <this-repository-url>
cd <repository-folder>

# 2. Create your local password file (edit the passwords if you like;
#    use letters, digits, - and _ only)
cp .env.example .env

# 3. Create the TLS certificates. Do this BEFORE starting the database.
bash scripts/generate_certs.sh

# 4. Start MariaDB 13.1. --wait returns once the server is healthy.
#    On the first start, everything in sql/ runs automatically.
docker compose up -d --wait

# 5. Install the two Python libraries in a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Check the version:
```bash
docker exec university-db mariadb -uroot -p -e "SELECT VERSION();"
# Enter the MARIADB_ROOT_PASSWORD from .env
# VERSION()
# 13.1.2-MariaDB-ubu2604
```

**What Docker is doing:** the *image* is a ready-made package with Ubuntu and MariaDB 13.1. The
*container* `university-db` is one running copy of it. `ports: 3306:3306` makes it reachable at
`localhost:3306`. The `sql/` folder is mounted at `/docker-entrypoint-initdb.d`, and the image runs
those files in alphabetical order (`01_`, `02_`, ...) **the first time** the database is created.

**Starting over:** the setup scripts run only on a fresh database. After changing anything in `sql/`
or `.env`, reset with:
```bash
docker compose down -v        # -v also deletes the stored data
docker compose up -d --wait
```

**Troubleshooting**

| Problem | Fix |
|---|---|
| Container exits right away, log mentions `server-cert.pem` | You started Docker before step 3. Run `docker compose down -v`, then `rm -rf certs`, `bash scripts/generate_certs.sh` and `docker compose up -d --wait`. |
| `04_users.sh: Permission denied` in `docker logs university-db` | The file lost its execute bit: `chmod +x sql/04_users.sh`, then reset. |
| Port 3306 already in use | Another MySQL/MariaDB is running locally. Stop it, or change the left side of `"3306:3306"`. |
| `ERROR 1045` everywhere after editing `.env` | Passwords are set only at first start. Reset with `docker compose down -v`. |

## 11. Running the demo

```bash
python app/demo.py professor     # or: student, finance, admin
python app/demo.py               # all four roles, one after another
```

Every role tries the **same six actions**, and MariaDB decides the outcome. Real output for the professor:

```
======================================================================
 ROLE: professor
======================================================================
Logged in as : smith_professor@%   (active role: professor_role)
TLS          : TLSv1.3  TLS_AES_256_GCM_SHA384  (certificate verified)

  ALLOWED  Read the course list  (4 rows returned)
  ALLOWED  Read my own grades (view)  (0 rows returned)
  ALLOWED  Read student contact details  (5 rows returned)
  ALLOWED  Read ALL grades  (7 rows returned)
  ALLOWED  Change a grade
  DENIED   Read financial records (IBANs)
           MariaDB error 1142: SELECT command denied to user 'smith_professor'@'192.168.65.1' for table `university`.`financial_records`
```

(The professor's "my own grades" returns 0 rows because the professor is not a student. The IP
address is how Docker Desktop shows your computer. "Change a grade" sets grade 1 to the value it
already has, so the demo never changes the data.)

### Interactive menu

To click through it yourself instead:

```bash
python app/menu.py
```

You choose a role, then pick actions from a numbered menu. You can switch user at any time. **Every
option is shown to every role on purpose.** The menu does not hide anything, so you can watch
MariaDB refuse what the role is not allowed to do. Real output, logged in as the student:

```
--- Logged in as student ---
  1. View courses
  2. View my grades
  3. View students
  4. View all grades
  5. Change a grade
  6. View financial records
  7. Switch user
  0. Quit
Choose an action: 6

View financial records:

  MariaDB refused the request (error 1142): SELECT command denied to user 'alice_student'@'192.168.65.1' for table `university`.`financial_records`
```

"Change a grade" asks you for a grade id and a new value. Those values are sent as **query
parameters** (`%s`), never pasted into the SQL text, so they cannot be used for SQL injection.
Unlike `demo.py`, this option really changes the data. Run `docker compose down -v` and
`docker compose up -d --wait` to reset it.

## 12. Running the security tests

```bash
python tests/run_all.py              # everything
python tests/test_permissions.py     # roles, GRANT, DENY
python tests/test_authentication.py  # ED25519
python tests/test_tls.py             # TLS
```

Each "attack" deliberately tries something that should not be allowed. A blocked attack counts as
`PASS` **only if MariaDB returns the exact expected error code** (for example `1142` for a table
privilege, `1045` for a failed login). So a test cannot pass by accident because of an unrelated
error such as a typo. The script exits with code `1` if any check fails.

**Do the tests really test something?** Yes. We temporarily removed the DENY
(`REVOKE DENY SELECT ON university.financial_records FROM professor_role`) and re-ran the permission tests:
```
[FAIL] Professor is blocked from financial_records (DENY)
       it was ALLOWED, but it should have been blocked
[FAIL] DENY still wins after an explicit table-level GRANT
       it was ALLOWED, but it should have been blocked
10/12 checks passed
```
After restoring the DENY, all checks passed again.

## 13. Results

All results below come from running `python tests/run_all.py` against MariaDB 13.1.2
(**22/22 checks passed**).

| Attack / check | Expected | Result | MariaDB control |
|---|---|---|---|
| Professor reads `courses` | Allowed | PASS | GRANT (role) |
| Professor reads all `grades` | Allowed | PASS | GRANT (role) |
| Professor reads `financial_records` | Blocked (1142) | PASS | **DENY** |
| Admin later grants professor SELECT on `financial_records`, professor tries again | Blocked (1142) | PASS | **DENY beats GRANT** |
| Professor updates the `grade` column | Allowed | PASS | Column-level GRANT |
| Professor moves a grade to another student (`student_id`) | Blocked (1143) | PASS | Column-level GRANT |
| Student changes a grade | Blocked (1142) | PASS | Role permissions (no GRANT) |
| Student reads everyone's grades | Blocked (1142) | PASS | Role permissions (no GRANT) |
| Student reads own grades via `my_grades` | Allowed, exactly 2 rows | PASS | View + GRANT |
| Student reads `financial_records` | Blocked (1142) | PASS | Role permissions (no GRANT) |
| Finance reads `financial_records` | Allowed | PASS | GRANT (role) |
| Finance changes a grade | Blocked (1142) | PASS | Role permissions (no GRANT) |
| All accounts (incl. root) use ED25519 | Yes | PASS | Authentication plugin |
| Correct password | Allowed | PASS | Authentication |
| Wrong password | Blocked (1045) | PASS | Authentication |
| Unknown user | Blocked (1045) | PASS | Authentication |
| Stolen `authentication_string` used as password | Blocked (1045) | PASS | ED25519 stores only a public key |
| Correct TLS + verification | Allowed | PASS | TLS |
| Client trusts the wrong CA | Blocked | PASS | TLS certificate verification |
| Wrong host name for the certificate | Blocked | PASS | TLS host name verification |
| Plaintext connection | Blocked (3159) | PASS | `require_secure_transport` |
| TLS with verification turned off | Connects (lesson) | PASS | none: shows why verification is needed |

## 14. What each control protects

| Control | Question it answers | Protects against |
|---|---|---|
| **Authentication (ED25519)** | *Who is connecting?* | Strangers and wrong passwords. Also against reuse of a stolen password table, because only public keys are stored. |
| **Roles + GRANT** | *What may this type of user do?* | Users doing things outside their job, like a student changing grades or finance touching academic data. |
| **DENY** | *What must this user never do, even if something else allows it?* | Over-broad grants and later mistakes. The professor's broad `SELECT` and even a later direct GRANT cannot expose bank details. |
| **TLS + verification** | *Is the connection private, and is the server really ours?* | Eavesdropping on the network, and talking to an impostor server. |

**Why MariaDB enforces the rules instead of Python:** the Python program is only one of many ways to
reach the database. Anyone with a password can also connect with the `mariadb` command-line tool,
a GUI like DBeaver, or their own script. Checks inside the Python code would simply be skipped by
those clients. Rules inside MariaDB apply to **every** client, because every query has to pass
through the server.

## 15. What these controls do NOT protect against

* **TLS only protects data while it travels.** It does not help if someone already has access to the
  server machine or the database files, or if the client computer is compromised.
* **Authentication does not decide permissions.** A successful login only proves *who* you are.
  Roles and grants decide *what* you may do.
* **Roles and DENY do not restrict root.** Anyone holding the root password (or full access to the
  server machine) can simply `REVOKE DENY`. Protect admin accounts separately.
* **DENY does not replace good permission design.** "Grant everything, then deny a few things" is
  fragile. Use DENY for clear exceptions like ours, not as the main tool.
* **Permissions do not stop misuse of legitimate access.** Finance can copy every IBAN it is allowed to
  read. The database cannot tell a legitimate read from a leak.
* **ED25519 does not stop weak passwords.** Someone who guesses `password123` gets in. MariaDB's
  password-validation plugins are a possible next step.
* **The `my_grades` view trusts the `db_username` column.** Anyone who can edit `students.db_username`
  (here: admin) could link an account to another student's grades.
* **Development shortcuts in this repo:** the passwords are passed to the container as environment
  variables (visible with `docker inspect`), the server's private key is readable by everyone
  (`chmod 644`) so the container can read it, and the `.env` file stores passwords in plain text on
  your computer. All of these are fine for a local demo but not for production.

**Possible extensions** (left out to keep the project small): client certificates (`REQUIRE X509`),
PARSEC authentication with the C-based connector, password validation plugins, and the audit plugin
to log every denied query.

## 16. Repository layout

```
├── README.md                 this tutorial
├── docker-compose.yml        starts MariaDB 13.1 with TLS
├── .env.example              template for your passwords (copy it to .env)
├── requirements.txt          PyMySQL (+ ed25519 support), python-dotenv
├── sql/                      run automatically on the first start, in this order:
│   ├── 01_schema.sql         tables
│   ├── 02_data.sql           fake data
│   ├── 03_roles.sql          roles, GRANT, DENY, my_grades view
│   └── 04_users.sh           ED25519 users (shell script so passwords come from .env)
├── scripts/
│   └── generate_certs.sh     creates the CA and server certificate
├── app/
│   ├── database.py           opens verified-TLS connections. No security logic.
│   ├── demo.py               automatic demo: same actions for every role
│   └── menu.py               interactive menu version of the demo
└── tests/
    ├── checks.py             expect_allowed / expect_blocked helpers
    ├── test_permissions.py   attacks on roles, GRANT, DENY
    ├── test_authentication.py attacks on ED25519
    ├── test_tls.py           attacks on TLS
    └── run_all.py            runs all of the above
```

## 17. Team

| Name | Role in the project |
|---|---|
| _Team member 1_ | _..._ |
| _Team member 2_ | _..._ |

## 18. References

Official MariaDB documentation:

* [MariaDB 13.1 Feature in Focus: DENY / Negative Grants](https://mariadb.org/mariadb-13-1-feature-in-focus-deny-negative-grants/) (mariadb.org)
* [MariaDB 13.1 Changes & Improvements](https://mariadb.com/docs/release-notes/community-server/13.1/mariadb-13.1-changes-and-improvements)
* [GRANT](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/grant)
* [REVOKE](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/revoke)
* [SHOW GRANTS](https://mariadb.com/docs/server/reference/sql-statements/administrative-sql-statements/show/show-grants)
* [mysql.global_priv table](https://mariadb.com/docs/server/reference/system-tables/the-mysql-database-tables/mysql-global_priv-table)
* [Roles Overview](https://mariadb.com/docs/server/security/user-account-management/roles/roles_overview)
* [CREATE ROLE](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/create-role)
* [Authentication Plugins](https://mariadb.com/docs/server/reference/plugins/authentication-plugins)
* [Authentication Plugin – ed25519](https://mariadb.com/docs/server/reference/plugins/authentication-plugins/authentication-plugin-ed25519)
* [Authentication Plugin – PARSEC](https://mariadb.com/docs/server/reference/plugins/authentication-plugins/authentication-plugin-parsec)
* [Secure Connections Overview](https://mariadb.com/docs/server/security/encryption/data-in-transit-encryption/secure-connections-overview)
* [Enabling TLS on MariaDB Server](https://mariadb.com/docs/server/security/encryption/data-in-transit-encryption/data-in-transit-encryption-enabling-tls-on-mariadb-server)
* [Securing Connections for Client and Server](https://mariadb.com/docs/server/security/encryption/data-in-transit-encryption/securing-connections-for-client-and-server)

Other:

* [PyMySQL](https://github.com/PyMySQL/PyMySQL), the Python driver used here
* [Project assignment page](https://mariadb.org/bachelor_hackathon_2026-09/)
