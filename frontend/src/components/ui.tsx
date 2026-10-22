import { AlertTriangle, Check, Copy, Info, XCircle } from "lucide-react";
import { useState, type ButtonHTMLAttributes, type ReactNode } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-xl border border-slate-200 bg-white shadow-sm ${className}`}>{children}</div>;
}

export function CardHeader({ title, icon, action }: { title: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-slate-100 px-4 py-3">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-800">
        {icon}
        {title}
      </h2>
      {action}
    </div>
  );
}

type Variant = "primary" | "secondary" | "ghost";
const VARIANTS: Record<Variant, string> = {
  primary: "bg-accent-500 text-white hover:bg-accent-600 disabled:bg-accent-500/50",
  secondary: "border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 disabled:text-slate-400",
  ghost: "text-slate-600 hover:bg-slate-100 disabled:text-slate-300",
};

export function Button({
  variant = "secondary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-500 disabled:cursor-not-allowed ${VARIANTS[variant]} ${className}`}
      {...props}
    />
  );
}

export function LinkButton({
  href,
  children,
  variant = "primary",
  external = false,
}: {
  href: string;
  children: ReactNode;
  variant?: Variant;
  external?: boolean;
}) {
  return (
    <a
      href={href}
      {...(external ? { target: "_blank", rel: "noreferrer" } : {})}
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-500 ${VARIANTS[variant]}`}
    >
      {children}
    </a>
  );
}

export function Badge({ children, tone = "slate" }: { children: ReactNode; tone?: "slate" | "blue" | "green" | "red" | "amber" }) {
  const tones = {
    slate: "bg-slate-100 text-slate-700 ring-slate-200",
    blue: "bg-accent-50 text-accent-700 ring-accent-100",
    green: "bg-emerald-50 text-emerald-800 ring-emerald-200",
    red: "bg-red-50 text-red-800 ring-red-200",
    amber: "bg-amber-50 text-amber-900 ring-amber-200",
  };
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${tones[tone]}`}>
      {children}
    </span>
  );
}

export function useCopy(): [boolean, (text: string) => void] {
  const [copied, setCopied] = useState(false);
  const copy = (text: string) => {
    void navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return [copied, copy];
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, copy] = useCopy();
  return (
    <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => copy(text)} aria-label={`${label} to clipboard`}>
      {copied ? <Check size={14} aria-hidden /> : <Copy size={14} aria-hidden />}
      {copied ? "Copied" : label}
    </Button>
  );
}

export function CodeBlock({ code, language = "bash" }: { code: string; language?: string }) {
  return (
    <div className="group relative my-3 overflow-hidden rounded-lg border border-navy-800 bg-navy-950">
      <div className="flex items-center justify-between border-b border-navy-800 px-3 py-1.5">
        <span className="font-mono text-[11px] uppercase tracking-wide text-slate-400">{language}</span>
        <CopyCodeButton text={code} />
      </div>
      <pre className="overflow-x-auto p-3 font-mono text-[13px] leading-relaxed text-slate-100">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function CopyCodeButton({ text }: { text: string }) {
  const [copied, copy] = useCopy();
  return (
    <button
      type="button"
      onClick={() => copy(text)}
      className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs text-slate-300 hover:bg-navy-800 hover:text-white"
      aria-label="Copy code to clipboard"
    >
      {copied ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function Notice({ tone = "info", title, children }: { tone?: "info" | "warn" | "error"; title?: string; children: ReactNode }) {
  const styles = {
    info: ["border-accent-100 bg-accent-50 text-accent-700", <Info key="i" size={16} aria-hidden />],
    warn: ["border-amber-200 bg-amber-50 text-amber-900", <AlertTriangle key="w" size={16} aria-hidden />],
    error: ["border-red-200 bg-red-50 text-red-800", <XCircle key="e" size={16} aria-hidden />],
  } as const;
  const [classes, icon] = styles[tone];
  return (
    <div role={tone === "error" ? "alert" : "status"} className={`flex gap-2.5 rounded-lg border px-3.5 py-3 text-sm ${classes}`}>
      <span className="mt-0.5 shrink-0">{icon}</span>
      <div className="min-w-0">
        {title && <p className="font-semibold">{title}</p>}
        <div className="break-words">{children}</div>
      </div>
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-slate-500" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-accent-500" aria-hidden />
      {label}
    </span>
  );
}
