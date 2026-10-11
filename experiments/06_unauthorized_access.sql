-- @title Experiment 6: unauthorized tables and columns in the real university database
-- @goal Attack the production-like university database as each demo user, using every route to forbidden data that SQL offers.
-- @goal Confirm the application roles from sql/03_roles.sql hold under joins, subqueries, qualified names and other databases.
-- Read-only experiment: every attack is expected to FAIL, so no data is changed.

-- @phase demo
-- ===== alice_student (student_role) =====
-- @as alice_student
-- @why Control: the view she is allowed to use shows exactly her own 2 grades.
-- @expect rows 2
SELECT * FROM university.my_grades;

-- @why Trying to widen the view's filter with a tautology changes nothing: the filter is part of the view, not of her query.
-- @expect rows 2
SELECT * FROM university.my_grades WHERE 1 = 1 OR code = 'x';

-- @why The base table is closed to her.
-- @expect error 1142 grades
SELECT * FROM university.grades;

-- @why A join does not help: each table in the statement is checked.
-- @expect error 1142 financial_records
SELECT c.code, f.bank_iban FROM university.courses c, university.financial_records f;

-- @why Neither does a scalar subquery.
-- @expect error 1142 financial_records
SELECT (SELECT bank_iban FROM university.financial_records LIMIT 1) AS stolen;

-- @why The system schema is closed too.
-- @expect error 1142 user
SELECT * FROM mysql.user;

-- @why Metadata is filtered to what she may touch: she sees only courses and my_grades, not the other tables.
-- @expect excludes financial_records
SELECT table_name FROM information_schema.tables WHERE table_schema = 'university';

-- @why She cannot inspect other accounts' grants.
-- @expect error 1044
SHOW GRANTS FOR smith_professor@'%';

-- ===== smith_professor (professor_role) =====
-- @as smith_professor
-- @why The professor may read students and grades ...
-- @expect rows 7
SELECT s.last_name, g.grade FROM university.students s JOIN university.grades g ON g.student_id = s.student_id;

-- @why ... but joining in the DENIED table fails: the DENY is checked per table, not per statement.
-- @expect error 1142 financial_records
SELECT s.last_name, f.bank_iban FROM university.students s JOIN university.financial_records f ON f.student_id = s.student_id;

-- @why A different letter case is simply a different (non-existent) table on this case-sensitive server (lower_case_table_names=0), so it is not a way around the DENY.
-- @expect error 1146 FINANCIAL_RECORDS
SELECT * FROM university.FINANCIAL_RECORDS;

-- @why Column privilege: she may change a grade but not reassign it to another student.
-- @expect error 1143 student_id
UPDATE university.grades SET student_id = 2 WHERE grade_id = 1;

-- @why Only UPDATE(grade) was granted: no INSERT and no DELETE.
-- @expect error 1142 grades
INSERT INTO university.grades (grade_id, student_id, course_id, grade) VALUES (99, 1, 101, 1.0);

-- @expect error 1142 grades
DELETE FROM university.grades WHERE grade_id = 1;

-- @why She cannot create objects (for instance a view that would copy data elsewhere).
-- @expect error 1142
CREATE TABLE university.copy_of_students AS SELECT * FROM university.students;

-- ===== jones_finance (finance_role) =====
-- @as jones_finance
-- @expect error 1142 grades
SELECT * FROM university.grades;

-- @why Finance may read students to look people up, so a join of the two allowed tables works.
-- @expect rows 5
SELECT s.last_name, f.amount_paid FROM university.students s JOIN university.financial_records f ON f.student_id = s.student_id;

-- @expect error 1142 courses
SELECT * FROM university.courses;

-- ===== uni_admin (admin_role) =====
-- @as uni_admin
-- @why The administrator role is powerful inside the university database ...
-- @expect rows 5
SELECT * FROM university.financial_records;

-- @why ... but it is not a database superuser: no access to the system schema, no account management.
-- @expect error 1142 user
SELECT * FROM mysql.user;

-- @expect error 1227
CREATE USER evil@'%' IDENTIFIED BY 'x';

-- @why Granting himself global privileges: refused at login level (1045), the admin role holds no GRANT OPTION on *.*.
-- @expect error 1045
GRANT ALL ON *.* TO uni_admin@'%';

-- @takeaway Each attack fails at the table or column the statement touches. The professor's DENY holds inside joins, and the student's view cannot be widened.
-- @takeaway The roles are least-privilege: even uni_admin cannot reach mysql.* or create accounts, so a stolen admin password does not mean a stolen server.
