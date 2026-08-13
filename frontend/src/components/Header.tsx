interface HeaderProps {
  repos: string[];
  selectedRepos: Set<string>;
  onToggleRepo: (name: string) => void;
  onRunScan: () => void;
  running: boolean;
  starting: boolean;
  theme: "light" | "dark";
  onToggleTheme: () => void;
}

export function Header({
  repos,
  selectedRepos,
  onToggleRepo,
  onRunScan,
  running,
  starting,
  theme,
  onToggleTheme,
}: HeaderProps) {
  return (
    <header className="surface flex flex-wrap items-center justify-between gap-4 rounded-lg px-5 py-4">
      <div className="flex items-center gap-3">
        <div
          className="font-display flex h-11 w-11 flex-none items-center justify-center rounded-sm text-xl font-semibold"
          style={{ background: "var(--brand)", color: "var(--brand-ink)" }}
          aria-hidden
        >
          P4
        </div>
        <div>
          <h1 className="font-display m-0 text-lg leading-tight font-semibold tracking-tight">
            P4 <span className="ink-muted font-body text-xs font-normal">Proof-Driven Vulnerability Validation</span>
          </h1>
          <p className="ink-secondary m-0 text-[0.78rem]">Prepare &middot; Scan &middot; Validate &middot; Prove</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Repositories to scan">
          {repos.map((name) => {
            const checked = selectedRepos.has(name);
            return (
              <label
                key={name}
                className="font-mono flex cursor-pointer items-center gap-1.5 rounded-full border px-2.5 py-1 text-[0.72rem] transition-colors"
                style={{
                  borderColor: checked ? "var(--brand)" : "var(--border)",
                  background: checked ? "var(--brand-wash)" : "transparent",
                  color: checked ? "var(--brand)" : "var(--ink-secondary)",
                }}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => onToggleRepo(name)}
                  className="sr-only"
                />
                {name}
              </label>
            );
          })}
        </div>
        <button
          type="button"
          onClick={onRunScan}
          disabled={running || starting}
          className="cursor-pointer rounded-md border-none px-4 py-2 text-[0.82rem] font-semibold disabled:cursor-not-allowed disabled:opacity-60"
          style={{ background: "var(--brand)", color: "var(--brand-ink)" }}
        >
          {starting ? "Starting…" : running ? "Running…" : "Run scan"}
        </button>
        <button
          type="button"
          onClick={onToggleTheme}
          aria-label="Toggle color theme"
          title="Toggle color theme"
          className="surface ink-secondary flex h-9 w-9 cursor-pointer items-center justify-center rounded-md text-base"
        >
          {theme === "dark" ? "☀" : "☽"}
        </button>
      </div>
    </header>
  );
}
