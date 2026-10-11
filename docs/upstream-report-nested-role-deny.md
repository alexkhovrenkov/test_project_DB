# Draft bug report: DENY on an inherited role is not enforced until FLUSH PRIVILEGES

Prepared for the MariaDB Jira (project MDEV, component "Authentication and Privilege System"). It has **not
been filed** yet; this file is the text to file.

**Affects version:** 13.1.2 (`13.1.2-MariaDB-ubu2604`), Docker image
`quay.io/mariadb-foundation/mariadb-devel@sha256:ed1087249cadb93623dd3b11258ea9790ad8f49c328dae5a5ef726ff1cea2931`
(arm64 and x86_64). Feature: DENY / negative grants (MDEV-14443).

## Summary

`DENY` on a role that is granted to another role (an *inherited* role) has no effect on users whose active
role inherits it, until the privilege cache is rebuilt (`FLUSH PRIVILEGES`, or some later role `GRANT`).
Users keep the denied access - also in connections opened after the `DENY`. This is fail-open.

The [DENY reference](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/deny)
says denies travel through the role graph and that a deny on any held role beats a grant on any other role,
at any depth. That holds only after the rebuild.

## How to repeat

Fresh server, no other configuration. As root:

```sql
CREATE DATABASE db1;
CREATE TABLE db1.t (id INT);
INSERT INTO db1.t VALUES (1);
CREATE ROLE r_parent;
CREATE ROLE r_child;
GRANT SELECT ON db1.* TO r_parent;
GRANT r_child TO r_parent;            -- r_parent inherits r_child
CREATE USER u1@'%' IDENTIFIED BY 'Repro-Passw0rd-1';
GRANT r_parent TO u1@'%';
SET DEFAULT ROLE r_parent FOR u1@'%';
DENY SELECT ON db1.t TO r_child;      -- the deny is on the INHERITED role
```

Then, as `u1`, in a **new** connection:

```sql
SELECT CURRENT_ROLE();   -- r_parent
SELECT * FROM db1.t;
```

**Expected:** `ERROR 1142 (42000): SELECT command denied to user 'u1'@... for table db1.t`

**Actual (13.1.2):**
```
+------+
| id   |
+------+
|    1 |
+------+
```

After `FLUSH PRIVILEGES` as root, a new `u1` connection gets the expected
`ERROR 1142 (42000) at line 1: SELECT command denied to user 'u1'@'localhost' for table db1.t`.

## Narrowing it down (all on the same build)

| Variant | Result without FLUSH |
|---|---|
| DENY on the user's **active** role (`r_parent`) | enforced immediately, even in an open session |
| DENY on the **account** (`u1@'%'`) | enforced immediately |
| DENY on a role one level down (direct child of the active role) | **not enforced** |
| DENY on a role three levels down | **not enforced** |
| DENY on a sibling role (another child of the active role) | **not enforced** |
| DENY created **before** `GRANT r_child TO r_parent` | enforced (the GRANT rebuilds the graph) |
| any later role `GRANT` (e.g. `GRANT r_x TO r_child`) after the DENY | enforced from then on |
| `REVOKE DENY` on a nested role | takes effect immediately |
| ordinary `GRANT` / `REVOKE` of a privilege on a nested role | take effect immediately |

So only *adding* a deny to an inherited role fails to propagate to the roles that inherit it.

## Impact

An administrator who denies access through a role hierarchy believes the access is closed while it is
still open, with no warning, until some unrelated statement or a server restart rebuilds the graph.

## Workaround

Run `FLUSH PRIVILEGES` after `DENY` on any role that other roles inherit, and test the effective access; or
attach the deny to the active role or to the accounts.

## Where this is demonstrated

In <https://github.com/alexkhovrenkov/test_project_DB>: `experiments/02_multi_role_inheritance.sql` (step by
step) and `tests/test_deny_semantics.py::test_deny_in_a_nested_role_beats_grant_in_another_branch_after_flush`
(asserts the current behaviour, and says so if a newer build fixes it).
