// Facts about the project shown in the UI. Everything else comes live from MariaDB.
export const REPOSITORY_URL = "https://github.com/alexkhovrenkov/test_project_DB";
export const ASSIGNMENT_URL = "https://mariadb.org/bachelor_hackathon_2026-09/";
export const AREA = { number: 5, title: "Authentication and access control" };
export const VERIFIED_VERSION = "13.1.2-MariaDB-ubu2604";

export const ROLE_INFO = {
  student: { label: "Student", account: "alice_student", role: "student_role" },
  professor: { label: "Professor", account: "smith_professor", role: "professor_role" },
  finance: { label: "Finance", account: "jones_finance", role: "finance_role" },
  admin: { label: "Admin", account: "uni_admin", role: "admin_role" },
} as const;
