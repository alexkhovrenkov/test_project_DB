-- 03_roles.sql
-- Creates one ROLE per type of university user and gives each role its
-- permissions with GRANT (allow) and DENY (forbid).
--
-- A ROLE is a named bundle of privileges. We give privileges to the role
-- once, then give the role to users. If a new professor joins, we only run
-- "GRANT professor_role TO new_user" instead of repeating every privilege.

USE university;

CREATE ROLE student_role;
CREATE ROLE professor_role;
CREATE ROLE finance_role;
CREATE ROLE admin_role;


-- ---------------------------------------------------------------------------
-- STUDENT: may see the course catalogue and ONLY THEIR OWN grades.
-- ---------------------------------------------------------------------------

-- A view is a saved SELECT that behaves like a read-only table.
-- USER() returns the account that is connected, e.g. 'alice_student@172.18.0.1'.
-- SUBSTRING_INDEX(..., '@', 1) keeps the part before '@' -> 'alice_student'.
-- So each student only sees the rows where students.db_username is their name.
-- (The view runs with the privileges of its creator, root, so the student does
--  NOT need access to the grades table itself.)
CREATE VIEW my_grades AS
    SELECT c.code, c.title, g.grade
    FROM grades g
    JOIN students s ON s.student_id = g.student_id
    JOIN courses  c ON c.course_id  = g.course_id
    WHERE s.db_username = SUBSTRING_INDEX(USER(), '@', 1);

GRANT SELECT ON university.courses   TO student_role;
GRANT SELECT ON university.my_grades TO student_role;
-- No privilege on grades, students or financial_records -> all blocked.


-- ---------------------------------------------------------------------------
-- PROFESSOR: may read "everything in the database except financial_records",
-- and may change the grade column of grades.
-- ---------------------------------------------------------------------------

-- Broad positive privilege: SELECT on every table in the database.
-- (Including tables that will be created in the future.)
GRANT SELECT ON university.* TO professor_role;

-- Column-level privilege: professors can UPDATE the grade column only,
-- not e.g. which student a grade belongs to.
GRANT UPDATE (grade) ON university.grades TO professor_role;

-- DENY (new in MariaDB 13.1): a NEGATIVE privilege.
-- It wins over the GRANT above, and over any GRANT given later, until it is
-- removed with REVOKE DENY. Without DENY we would have to GRANT SELECT on
-- students, courses and grades one by one and remember to do the same for
-- every new table.
DENY SELECT ON university.financial_records TO professor_role;


-- ---------------------------------------------------------------------------
-- FINANCE: works with financial_records, may look up who a student is,
-- has NO access to grades.
-- ---------------------------------------------------------------------------
GRANT SELECT ON university.students TO finance_role;
GRANT SELECT, INSERT, UPDATE ON university.financial_records TO finance_role;


-- ---------------------------------------------------------------------------
-- ADMIN: everything inside the university database (but not other databases,
-- and not the right to create MariaDB users - that stays with root).
-- ---------------------------------------------------------------------------
GRANT ALL PRIVILEGES ON university.* TO admin_role;
