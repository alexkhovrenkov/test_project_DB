import { ArrowRight, BookOpen, ChartColumn, ExternalLink, FlaskConical, KeyRound, Lock, Search, ShieldBan, ShieldCheck, Users } from "lucide-react";
import type { ReactNode } from "react";
import { Card, CodeBlock, LinkButton } from "../components/ui";
import { AREA, ASSIGNMENT_URL, REPOSITORY_URL } from "../lib/project";
import { hrefFor } from "../lib/router";

const CONTROLS: { icon: ReactNode; title: string; text: string }[] = [
  {
    icon: <Users size={18} aria-hidden />,
    title: "Roles and GRANT",
    text: "Four roles (student, professor, finance, admin) hold every privilege. Accounts only receive a role.",
  },
  {
    icon: <ShieldBan size={18} aria-hidden />,
    title: "DENY (new in 13.1)",
    text: "Professors may read the whole database except financial_records. The DENY beats any GRANT, including later ones.",
  },
  {
    icon: <KeyRound size={18} aria-hidden />,
    title: "ED25519 and unix_socket",
    text: "The server stores only a public key. Root has no password at all, and no password is in any file.",
  },
  {
    icon: <Lock size={18} aria-hidden />,
    title: "Verified TLS",
    text: "require_secure_transport=ON. The client checks the certificate chain and host name, not only encryption.",
  },
];

const FEATURES: { icon: ReactNode; title: string; text: string; href: string; cta: string }[] = [
  {
    icon: <Search size={20} aria-hidden />,
    title: "Explore",
    text: "21 preloaded statements. Each one says what MariaDB should answer and why, then runs it for real.",
    href: hrefFor("playground"),
    cta: "Open the examples",
  },
  {
    icon: <FlaskConical size={20} aria-hidden />,
    title: "Experiment",
    text: "Edit the SQL and switch between the four accounts. MariaDB, not this app, decides what is allowed.",
    href: hrefFor("playground"),
    cta: "Write your own query",
  },
  {
    icon: <ChartColumn size={20} aria-hidden />,
    title: "Analyze",
    text: "Run the access matrix, failed-login error codes and TLS timing live. Every number is measured on your server.",
    href: hrefFor("analytics"),
    cta: "Run a benchmark",
  },
];

export default function Home() {
  return (
    <div className="space-y-12">
      <section className="grid gap-8 lg:grid-cols-[1.25fr_1fr] lg:items-center">
        <div>
          <a
            href={ASSIGNMENT_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 rounded-full bg-accent-50 px-3 py-1 text-xs font-semibold text-accent-700 ring-1 ring-accent-100"
          >
            Area {AREA.number} · {AREA.title}
          </a>
          <h1 className="mt-4 text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl">
            Protecting a university database with MariaDB 13.1
          </h1>
          <p className="mt-4 max-w-2xl text-lg leading-relaxed text-slate-600">
            A small university database holds grades and bank details. Roles, <code className="font-mono">DENY</code>, ED25519
            logins and verified TLS decide who may see what. This lab runs real SQL as each user, so you can watch MariaDB
            allow and refuse.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <LinkButton href={hrefFor("playground")}>
              Open SQL Playground <ArrowRight size={16} aria-hidden />
            </LinkButton>
            <LinkButton href={hrefFor("docs")} variant="secondary">
              <BookOpen size={16} aria-hidden /> Read Documentation
            </LinkButton>
          </div>
          <p className="mt-4 text-sm text-slate-500">
            Source and full README:{" "}
            <a href={REPOSITORY_URL} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent-700 hover:underline">
              {REPOSITORY_URL.replace("https://", "")} <ExternalLink size={13} aria-hidden />
            </a>
          </p>
        </div>
        <Card className="p-5">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">The core idea, in SQL</p>
          <CodeBlock
            language="sql"
            code={`-- sql/03_roles.sql
GRANT SELECT ON university.* TO professor_role;
DENY  SELECT ON university.financial_records TO professor_role;

-- as smith_professor:
SELECT * FROM grades;             -- 7 rows
SELECT * FROM financial_records;  -- ERROR 1142`}
          />
          <p className="text-sm text-slate-600">
            One broad grant and one negative grant. There is no <code className="font-mono">if role == ...</code> in the
            application. Every decision you see is made by MariaDB.
          </p>
        </Card>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-slate-900">What MariaDB does in this project</h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {CONTROLS.map((control) => (
            <Card key={control.title} className="p-4">
              <div className="flex items-center gap-2 text-accent-700">
                {control.icon}
                <h3 className="font-semibold text-slate-900">{control.title}</h3>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-slate-600">{control.text}</p>
            </Card>
          ))}
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        {FEATURES.map((feature) => (
          <a key={feature.title} href={feature.href} className="group">
            <Card className="h-full p-5 transition-shadow group-hover:shadow-md">
              <span className="grid h-10 w-10 place-items-center rounded-lg bg-navy-900 text-accent-100">{feature.icon}</span>
              <h3 className="mt-4 text-lg font-semibold text-slate-900">{feature.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-600">{feature.text}</p>
              <span className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-accent-700">
                {feature.cta} <ArrowRight size={14} aria-hidden className="transition-transform group-hover:translate-x-0.5" />
              </span>
            </Card>
          </a>
        ))}
      </section>

      <section>
        <Card className="p-5">
          <div className="flex items-center gap-2">
            <ShieldCheck size={18} className="text-accent-700" aria-hidden />
            <h2 className="font-semibold text-slate-900">Start it on your machine</h2>
          </div>
          <p className="mt-1 text-sm text-slate-600">
            Needs Docker, Python 3.10+ and Node.js 20+. No password to configure.
          </p>
          <CodeBlock
            code={`git clone ${REPOSITORY_URL}.git && cd test_project_DB
make lab        # certificates, MariaDB 13.1, venv, frontend build -> http://127.0.0.1:8000`}
          />
        </Card>
      </section>
    </div>
  );
}
