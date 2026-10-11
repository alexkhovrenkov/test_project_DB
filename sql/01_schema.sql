-- 01_schema.sql
-- Creates the small university database: 4 tables.
-- Files in this folder run in alphabetical order, which is why they start
-- with 01_, 02_, ... (schema must exist before data, roles and users).

CREATE DATABASE university;
USE university;

-- Normal, low-sensitivity information.
CREATE TABLE students (
    student_id  INT PRIMARY KEY,           -- unique id of each student
    first_name  VARCHAR(50)  NOT NULL,
    last_name   VARCHAR(50)  NOT NULL,
    email       VARCHAR(100) NOT NULL,
    program     VARCHAR(100) NOT NULL,
    -- The MariaDB account that belongs to this student (NULL = no account).
    -- Used by the my_grades view in 03_roles.sql.
    db_username VARCHAR(80)  NULL UNIQUE
);

CREATE TABLE courses (
    course_id   INT PRIMARY KEY,
    code        VARCHAR(10)  NOT NULL,
    title       VARCHAR(100) NOT NULL,
    credits     INT          NOT NULL,
    professor   VARCHAR(100) NOT NULL
);

-- Academic data: who may CHANGE it matters.
CREATE TABLE grades (
    grade_id    INT PRIMARY KEY,
    student_id  INT          NOT NULL,
    course_id   INT          NOT NULL,
    grade       DECIMAL(2,1) NOT NULL,     -- e.g. 1.3 (German-style scale 1.0-5.0)
    FOREIGN KEY (student_id) REFERENCES students(student_id),
    FOREIGN KEY (course_id)  REFERENCES courses(course_id)
);

-- Sensitive data: who may even READ it matters.
CREATE TABLE financial_records (
    record_id    INT PRIMARY KEY,
    student_id   INT           NOT NULL,
    tuition_due  DECIMAL(8,2)  NOT NULL,
    amount_paid  DECIMAL(8,2)  NOT NULL,
    scholarship  VARCHAR(100)  NULL,
    bank_iban    VARCHAR(34)   NOT NULL,   -- fake bank account numbers
    FOREIGN KEY (student_id) REFERENCES students(student_id)
);
