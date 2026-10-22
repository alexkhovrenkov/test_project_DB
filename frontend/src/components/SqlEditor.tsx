import Prism from "prismjs";
import "prismjs/components/prism-sql";
import EditorModule from "react-simple-code-editor";

// The package is CommonJS: depending on the bundler its default import is the component
// or a module object holding it. Unwrap once so both dev and production builds work.
const Editor = ((EditorModule as unknown as { default?: typeof EditorModule }).default ?? EditorModule) as typeof EditorModule;

export function highlightSql(code: string): string {
  return Prism.highlight(code, Prism.languages.sql, "sql");
}

export function SqlEditor({
  value,
  onChange,
  onRun,
}: {
  value: string;
  onChange: (value: string) => void;
  onRun: () => void;
}) {
  return (
    <div className="sql-code min-h-[180px] rounded-lg border border-slate-200 bg-slate-50 focus-within:border-accent-500 focus-within:ring-2 focus-within:ring-accent-100">
      <Editor
        value={value}
        onValueChange={onChange}
        highlight={highlightSql}
        padding={14}
        textareaId="sql-editor"
        aria-label="SQL statement"
        onKeyDown={(event) => {
          if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
            event.preventDefault();
            onRun();
          }
        }}
        className="font-mono text-[13.5px] leading-relaxed"
        style={{ minHeight: 180 }}
      />
    </div>
  );
}
