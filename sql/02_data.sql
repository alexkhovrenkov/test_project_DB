-- 02_data.sql
-- Fake, made-up data. No real people, no real bank accounts.

USE university;

INSERT INTO students (student_id, first_name, last_name, email, program, db_username) VALUES
    (1, 'Alice',  'Meyer',   'alice.meyer@uni.example',   'Computer Science', 'alice_student'),
    (2, 'Ben',    'Okafor',  'ben.okafor@uni.example',    'Computer Science', NULL),
    (3, 'Chiara', 'Rossi',   'chiara.rossi@uni.example',  'Mathematics',      NULL),
    (4, 'Deniz',  'Yilmaz',  'deniz.yilmaz@uni.example',  'Physics',          NULL),
    (5, 'Emma',   'Larsen',  'emma.larsen@uni.example',   'Computer Science', NULL);

INSERT INTO courses (course_id, code, title, credits, professor) VALUES
    (101, 'CS201', 'Databases',               6, 'Prof. Smith'),
    (102, 'CS105', 'Programming in Python',   6, 'Prof. Smith'),
    (103, 'MA110', 'Linear Algebra',          8, 'Prof. Novak'),
    (104, 'CS310', 'Computer Networks',       5, 'Prof. Novak');

INSERT INTO grades (grade_id, student_id, course_id, grade) VALUES
    (1, 1, 101, 1.3),
    (2, 1, 102, 2.0),
    (3, 2, 101, 2.7),
    (4, 3, 103, 1.0),
    (5, 4, 104, 3.3),
    (6, 5, 101, 1.7),
    (7, 5, 102, 2.3);

-- IBANs below use the format of German IBANs but are invented.
INSERT INTO financial_records (record_id, student_id, tuition_due, amount_paid, scholarship, bank_iban) VALUES
    (1, 1, 1500.00, 1500.00, NULL,                   'DE00 1234 5678 0000 0001 01'),
    (2, 2, 1500.00,  750.00, NULL,                   'DE00 1234 5678 0000 0002 02'),
    (3, 3, 1500.00,    0.00, 'Merit Scholarship',    'DE00 1234 5678 0000 0003 03'),
    (4, 4, 1500.00, 1500.00, NULL,                   'DE00 1234 5678 0000 0004 04'),
    (5, 5, 1500.00, 1000.00, 'Women in CS Grant',    'DE00 1234 5678 0000 0005 05');
