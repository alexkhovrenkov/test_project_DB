import { ExternalLink } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Card, CodeBlock } from "../components/ui";
import { ASSIGNMENT_URL, REPOSITORY_URL, VERIFIED_VERSION } from "../lib/project";

const README = `${REPOSITORY_URL}#readme`;
const file = (path: string) => `${REPOSITORY_URL}/blob/main/${path}`;

const SECTIONS = [
  { id: "overview", title: "Project Overview" },
  { id: "feature", title: "MariaDB Feature Explained" },
  { id: "architecture", title: "Architecture" },
  { id: "schema", title: "Database Schema" },
  { id: "setup", title: "Installation and Setup" },
  { id: "examples", title: "Example Queries" },
  { id: "findings", title: "Results and Findings" },
  { id: "limits", title: "Limitations and Troubleshooting" },
];

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className="scroll-mt-20 border-b border-slate-100 pb-8 last:border-0">
      <h2 className="text-xl font-semibold tracking-tight text-slate-900">{title}</h2>
      <div className="mt-3 space-y-3 text-[15px] leading-relaxed text-slate-700">{children}</div>
    </section>
  );
}

function Ref({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="text-accent-700 hover:underline">
      {children}
    </a>
  );
}

const Code = ({ children }: { children: ReactNode }) => (
  <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[13px] text-slate-800">{children}</code>
);

function Table({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200">
      <table className="min-w-full text-left text-sm">
        <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            {head.map((cell) => (
              <th key={cell} className="border-b border-slate-200 px-3 py-2 font-semibold">
                {cell}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index} className="border-b border-slate-100 align-top last:border-0">
              {row.map((cell, cellIndex) => (
                <td key={cellIndex} className="px-3 py-2">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Docs() {
  const [active, setActive] = useState(SECTIONS[0].id);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: "-80px 0px -60% 0px" },
    );
    SECTIONS.forEach((section) => {
      const element = document.getElementById(section.id);
      if (element) observer.observe(element);
    });
    return () => observer.disconnect();
  }, []);

  const jump = (id: string) => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });

  return (
    <div className="grid gap-8 lg:grid-cols-[220px_1fr]">
      <aside className="lg:sticky lg:top-20 lg:h-fit">
        <p className="px-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Documentation</p>
        <nav className="mt-2 flex gap-1 overflow-x-auto lg:flex-col" aria-label="Documentation sections">
          {SECTIONS.map((section, index) => (
            <button
              key={section.id}
              type="button"
              onClick={() => jump(section.id)}
              className={`whitespace-nowrap rounded-md px-2.5 py-1.5 text-left text-sm transition-colors ${
                active === section.id ? "bg-accent-50 font-medium text-accent-700" : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              {index + 1}. {section.title}
            </button>
          ))}
        </nav>
        <a href={README} target="_blank" rel="noreferrer" className="mt-4 flex items-center gap-1 px-2 text-sm text-accent-700 hover:underline">
          Full README on GitHub <ExternalLink size={13} aria-hidden />
        </a>
      </aside>

      <Card className="min-w-0 space-y-8 p-6 sm:p-8">
        <Section id="overview" title="1. Project Overview">
          <p>
            A project for <strong>area 5, "Authentication and access control"</strong> of the{" "}
            <Ref href={ASSIGNMENT_URL}>MariaDB student database projects, 2026-09</Ref>. The area asks for "a database secure
            by configuration rather than by convention": roles and <Code>DENY</Code> instead of per-user grants, an
            authentication method instead of a password in a configuration file, verified TLS, and an attack against each
            control.
          </p>
          <p>
            A fictional university keeps students, courses, grades and bank details in one database. Four accounts (a
            student, a professor, the finance office and an administrator) each get one role. The Python code only sends SQL
            and prints MariaDB's answer; there is no permission logic in the application. This lab is a window onto the same
            code: it runs your SQL as one of those accounts.
          </p>
          <p>
            The root <Ref href={README}>README</Ref> is the complete reference. It covers 14 experiments, findings, the
            attack table and test results. This page is a summary.
          </p>
        </Section>

        <Section id="feature" title="2. MariaDB Feature Explained">
          <Table
            head={["Capability", "What it does here", "Why MariaDB"]}
            rows={[
              [<Code>DENY</Code>, "Professors read university.* except financial_records; the DENY beats every GRANT, also later ones.", "New in MariaDB 13.1 (MDEV-14443). MySQL 8 and PostgreSQL have no negative grants."],
              ["Roles", "student_role, professor_role, finance_role, admin_role; accounts get a role and a default role.", "MariaDB's role model: one active role, roles inside roles."],
              ["Column privileges", "GRANT UPDATE (grade): a professor corrects a grade but cannot reassign it (1143).", "Standard, combined with DENY."],
              [<Code>ed25519</Code>, "All four accounts. The server stores only a public key; the password never crosses the network.", "Ships with MariaDB (auth_ed25519). A stolen mysql.user does not let anyone log in."],
              [<Code>unix_socket</Code>, "root@localhost has no password; only the OS user root in the container (docker exec) can use it.", "MariaDB's default for root since 10.4."],
              ["Verified TLS", "require_secure_transport=ON, TLS 1.2/1.3; the client checks certificate chain and host name.", "Plaintext is refused (3159). Unverified TLS would not stop an impostor server."],
              ["Password plugins", "simple_password_check and password_reuse_check refuse weak and reused passwords (1819).", "MariaDB plugins; the project found two undocumented behaviours (findings 9, 10)."],
            ]}
          />
          <p>
            Classic SQL access control only adds privileges: a user can do whatever the union of their grants allows. With{" "}
            <Code>DENY</Code> there is a ceiling. <Code>GRANT SELECT ON university.*</Code> plus{" "}
            <Code>DENY SELECT ON university.financial_records</Code> is a complete rule that no later grant can widen. That is
            why it is the right tool for "professors never read bank details". Documentation:{" "}
            <Ref href="https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/deny">DENY</Ref>,{" "}
            <Ref href="https://mariadb.com/docs/server/reference/plugins/authentication-plugins">authentication plugins</Ref>,{" "}
            <Ref href="https://mariadb.com/docs/server/security/user-account-management">user account management</Ref>.
          </p>
        </Section>

        <Section id="architecture" title="3. Architecture">
          <CodeBlock
            language="text"
            code={`Browser (React, frontend/)  --HTTP, 127.0.0.1 only-->  app/lab_server.py (stdlib HTTP, JSON API)
                                                              |
                                                       app/lab.py  (statement check, rollback,
                                                              |      timeouts, benchmarks)
                                                              |
                                         app/database.py ===TLS 1.2/1.3, cert + host verified===> MariaDB 13.1
                                         (ED25519 login as alice_student / smith_professor /        (Docker)
                                          jones_finance / uni_admin)                                   ^
                                                                                                       | unix_socket
                                         app/admin.py --docker exec mariadb (root, no password)--------+
                                         (creates the run's temporary harness admin: REQUIRE X509,
                                          random in-memory password; gives the demo accounts
                                          random in-memory passwords)`}
          />
          <ul className="list-disc space-y-1 pl-5">
            <li>
              <strong>frontend/</strong>: React, TypeScript, Vite, Tailwind CSS, Recharts. It holds no credentials and only
              calls <Code>/api/*</Code>.
            </li>
            <li>
              <strong>app/lab_server.py</strong>: six endpoints (<Code>/api/health</Code>, <Code>/api/examples</Code>,{" "}
              <Code>/api/query</Code>, <Code>/api/stats</Code>, <Code>/api/scenarios</Code>, <Code>/api/benchmark</Code>). It
              also serves the built frontend. It listens on 127.0.0.1, accepts only JSON POSTs and refuses foreign Host
              headers.
            </li>
            <li>
              <strong>app/lab.py</strong>: runs one statement as the chosen demo account. Only SELECT, SHOW, WITH, DESCRIBE,
              EXPLAIN and single INSERT/UPDATE/DELETE statements are accepted, always inside a transaction that is rolled
              back, with <Code>max_statement_time = 5</Code> and at most 200 rows.
            </li>
            <li>
              The rest of <Ref href={file("app")}>app/</Ref> (demo, interactive menu, SQL tutorial runner) and the test suite
              use the same connection code.
            </li>
          </ul>
        </Section>

        <Section id="schema" title="4. Database Schema">
          <CodeBlock
            language="text"
            code={`students (student_id PK, first_name, last_name, email, program, db_username UNIQUE)
courses  (course_id PK, code, title, credits, professor)
grades   (grade_id PK, student_id FK -> students, course_id FK -> courses, grade DECIMAL(2,1))
financial_records (record_id PK, student_id FK -> students, tuition_due, amount_paid, scholarship, bank_iban)
my_grades  VIEW: a student's own rows, WHERE students.db_username = the connected user`}
          />
          <ul className="list-disc space-y-1 pl-5">
            <li>
              <strong>The tables differ in sensitivity on purpose</strong>, so access control has something to separate:
              courses is public, students is personal, grades is "read by many, written by few", and financial_records is the
              crown jewel.
            </li>
            <li>
              <strong>db_username</strong> links a person to a MariaDB account, so the <Code>my_grades</Code> view can filter
              by <Code>USER()</Code>. This is row-level security in MariaDB, not in Python.
            </li>
            <li>
              <strong>grade DECIMAL(2,1)</strong> makes the column privilege meaningful: a professor may change the grade but
              not whose grade it is.
            </li>
            <li>
              The view's <strong>definer</strong> is a locked, localhost-only account with SELECT on three tables, not root.
              A definer view lends the definer's rights to every reader (experiment 9).
            </li>
          </ul>
          <p>
            Files: <Ref href={file("sql/01_schema.sql")}>sql/01_schema.sql</Ref>, <Ref href={file("sql/02_data.sql")}>02_data.sql</Ref>{" "}
            (made-up data), <Ref href={file("sql/03_roles.sql")}>03_roles.sql</Ref> (roles, GRANT, DENY, the view),{" "}
            <Ref href={file("sql/04_users.sql")}>04_users.sql</Ref> (locked ED25519 accounts),{" "}
            <Ref href={file("sql/05_password_policy.sql")}>05_password_policy.sql</Ref>,{" "}
            <Ref href={file("sql/06_lockdown.sh")}>06_lockdown.sh</Ref> (root to unix_socket).
          </p>
        </Section>

        <Section id="setup" title="5. Installation and Setup">
          <p>
            <strong>Requirements:</strong> Docker with Compose (Docker Desktop on macOS/Windows), Python 3.10+, Node.js 20+
            with npm (for the frontend), <Code>make</Code>, <Code>openssl</Code>, <Code>bash</Code>. On Windows, use WSL.{" "}
            <strong>MariaDB:</strong> 13.1 or newer (the first version with DENY). The project pins the exact build all
            results come from: <Code>{VERIFIED_VERSION}</Code>.
          </p>
          <p>One command does everything. It needs no password, because none exists:</p>
          <CodeBlock
            code={`git clone ${REPOSITORY_URL}.git && cd test_project_DB
make lab
# -> certificates, MariaDB 13.1 in Docker, Python venv, npm ci + build, then
#    MariaDB Interactive Lab: http://127.0.0.1:8000/`}
          />
          <p>
            On the first start the server loads the schema, data, roles and users from <Code>sql/</Code> automatically
            (Docker's <Code>/docker-entrypoint-initdb.d</Code>). To start over from an empty server, run{" "}
            <Code>make reset</Code>, then <Code>make lab</Code> again.
          </p>
          <p>Development (frontend with hot reload; the API in a second terminal):</p>
          <CodeBlock
            code={`make lab-api                    # terminal 1: MariaDB + API on http://127.0.0.1:8000
cd frontend && npm ci && npm run dev   # terminal 2: http://127.0.0.1:5173 (proxies /api)`}
          />
          <p>Without the web frontend, the original command-line workflow is unchanged:</p>
          <CodeBlock
            code={`make demo     # role demo, 5 tutorial examples, 13 experiments - every step PASS/FAIL
make test     # pytest: unit tests + integration tests against the real server
make lint     # ruff + shellcheck`}
          />
          <p>
            Settings (all optional, none secret) go in <Code>.env</Code>: <Code>MARIADB_PORT</Code>,{" "}
            <Code>MARIADB_CONTAINER</Code>, <Code>MARIADB_IMAGE</Code>, <Code>LAB_PORT</Code>. See{" "}
            <Ref href={file(".env.example")}>.env.example</Ref>.
          </p>
        </Section>

        <Section id="examples" title="6. Example Queries">
          <p>
            Each of these is preloaded in the SQL Playground. The documented answer is checked against the real server by{" "}
            <Ref href={file("tests/integration/test_lab.py")}>tests/integration/test_lab.py</Ref>.
          </p>
          <CodeBlock
            language="sql"
            code={`-- as smith_professor (professor_role): broad GRANT, one DENY
SELECT grade_id, student_id, course_id, grade FROM grades;   -- 7 rows
SELECT student_id, bank_iban FROM financial_records;         -- ERROR 1142 (DENY)
SHOW TABLES;                                                 -- financial_records is hidden
SELECT * FROM salaries_2026;                                 -- ERROR 1146: a missing table looks different

-- column privilege
UPDATE grades SET grade = 1.0 WHERE grade_id = 1;            -- 1 row affected
UPDATE grades SET student_id = 2 WHERE grade_id = 1;         -- ERROR 1143 (column)

-- as alice_student (student_role): row-level security with a definer view
SELECT code, title, grade FROM my_grades;                    -- only Alice's 2 rows
SELECT code, title, grade FROM my_grades WHERE grade > 0 OR 1 = 1;   -- still 2 rows

-- TLS, as any account
SHOW SESSION STATUS WHERE Variable_name IN ('Ssl_version', 'Ssl_cipher');   -- TLSv1.3`}
          />
          <p>
            The same lessons exist as annotated SQL files that run without the frontend:{" "}
            <Ref href={file("examples/README.md")}>examples/</Ref> (5 lessons, 10-minute start) and{" "}
            <Ref href={file("experiments")}>experiments/</Ref> (14 experiments).
          </p>
        </Section>

        <Section id="findings" title="7. Results and Findings">
          <p>
            Observed on 13.1.2. Each finding is reproduced by an experiment or a test that asserts the observed behaviour.
            The README's section 11 has all twelve.
          </p>
          <ul className="list-disc space-y-1.5 pl-5">
            <li>
              <strong>A DENY on an inherited role is not enforced until the role graph is rebuilt</strong> (FLUSH PRIVILEGES).
              This fails open. A bug report is prepared in{" "}
              <Ref href={file("docs/upstream-report-nested-role-deny.md")}>docs/upstream-report-nested-role-deny.md</Ref>.
            </li>
            <li>
              <strong>A role-attached DENY disappears with SET ROLE NONE</strong> if another grant still allows the access; a
              DENY on the account cannot be shed.
            </li>
            <li>
              <strong>A DENY on a user does not follow a SQL SECURITY DEFINER view</strong>; INVOKER views obey it.
            </li>
            <li>
              <strong>Error codes reveal that a denied table exists</strong> (1142 vs 1146), although SHOW TABLES hides it. Try
              both in the playground.
            </li>
            <li>
              <strong>DENY ... TO PUBLIC can lock out every administrator.</strong> <Code>make lockout</Code> reproduces the
              hard case on a disposable server.
            </li>
            <li>
              <strong>A unix_socket-only account opens a user-enumeration oracle</strong> (1698 instead of 1045 for unknown
              names). The project's root setup closes it; the Analytics page's "Failed logins" scenario measures it live.
            </li>
            <li>
              <strong>The password reuse history keeps refused passwords and survives DROP USER</strong>, and ALTER USER
              reports policy failures as the generic 1396.
            </li>
          </ul>
          <p>
            Verification: <Code>make demo</Code> (24/24 role-demo actions, 108 tutorial and 373 experiment steps),{" "}
            <Code>make test</Code> and CI on every push. See README section 13 for the current numbers and the CI link.
          </p>
        </Section>

        <Section id="limits" title="8. Limitations and Troubleshooting">
          <ul className="list-disc space-y-1 pl-5">
            <li>Anyone who can run <Code>docker exec</Code> on the host is database root. That is what unix_socket means here.</li>
            <li>
              Roles cannot tell use from misuse: finance may read, and therefore copy, every IBAN.
            </li>
            <li>
              The lab's timings come from one machine, Docker networking included. They are honest medians with spread, not a
              controlled benchmark.
            </li>
            <li>
              The lab accepts edited SQL, but only read statements and single writes that are always rolled back; DDL, GRANT,
              SET and multi-statement text are refused before they reach MariaDB.
            </li>
            <li>
              Starting the lab (like <Code>make demo</Code> and <Code>make test</Code>) gives the demo accounts new random
              passwords. Run <Code>make set-password USER=...</Code> afterwards to log in by hand.
            </li>
            <li>MariaDB 13.1 is a preview release; findings may change in newer builds.</li>
          </ul>
          <Table
            head={["Problem", "Fix"]}
            rows={[
              ["Red banner \"MariaDB unreachable\"", <>Start Docker Desktop, then <Code>make up</Code>. The lab retries on every request.</>],
              ["\"Cannot reach the lab backend\"", <>The Python server is not running: <Code>make lab</Code> (or <Code>make lab-api</Code> in development).</>],
              ["Page says the frontend is not built", <><Code>make lab</Code> builds it (needs Node.js and npm).</>],
              ["Port 8000 or 3306 is in use", <>Set <Code>LAB_PORT=8001</Code> or <Code>MARIADB_PORT=3307</Code> in <Code>.env</Code>.</>],
              ["CERTIFICATE_VERIFY_FAILED", <>Certificates and server are out of sync: <Code>make reset</Code>, <Code>rm -rf certs</Code>, <Code>make lab</Code>.</>],
            ]}
          />
        </Section>
      </Card>
    </div>
  );
}
