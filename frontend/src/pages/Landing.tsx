import { Link } from "react-router-dom";

const STAGES = [
  {
    n: "01",
    title: "Prepare",
    body: "Builds a lightweight map of the repo - files, symbols, HTTP entrypoints - with no build step required.",
  },
  {
    n: "02",
    title: "Scan",
    body: "Semgrep casts a wide net for injection, insecure deserialization, and SSRF. Deliberately noisy - that's the baseline.",
  },
  {
    n: "03",
    title: "Validate",
    body: "An LLM reads each candidate in context and decides real exploitability, clearing false positives a pattern-matcher can't.",
  },
  {
    n: "04",
    title: "Prove",
    body: "Writes a concrete proof-of-concept narrative for every confirmed finding - the exact request that would trigger it.",
  },
  {
    n: "05",
    title: "Verify",
    body: "Spins up an isolated sandbox and exploits the finding for real. Evidence, not just an LLM's word for it.",
  },
];

const STATS = [
  { value: "90–100%", label: "Precision after Validate", sub: "vs. ~69% for raw pattern-matching alone" },
  { value: "75–100%", label: "False positives suppressed", sub: "cleared by LLM exploitability triage" },
  { value: "100%", label: "Recall, both ways", sub: "suppressing noise without losing real findings" },
];

export function Landing() {
  return (
    <main className="flex-1" style={{ background: "var(--page)" }}>
      {/* Hero */}
      <section className="mx-auto max-w-6xl px-6 pt-24 pb-20 sm:px-10 sm:pt-32 sm:pb-28">
        <p className="font-mono mb-6 text-[0.78rem] tracking-[0.18em]" style={{ color: "var(--gold)" }}>
          PREPARE · SCAN · VALIDATE · PROVE · VERIFY
        </p>
        <h1 className="font-display m-0 max-w-3xl text-5xl leading-[1.08] font-semibold tracking-tight sm:text-6xl">
          Prove it before you trust it.
        </h1>
        <p className="ink-secondary mt-7 max-w-xl text-[1.05rem] leading-relaxed">
          P4 is a multi-stage agentic SAST engine. It doesn't just flag
          vulnerabilities and hope you believe it - it validates them with an
          LLM, then exploits them for real in an isolated sandbox before it
          asks for your trust.
        </p>
        <div className="mt-10 flex flex-wrap items-center gap-4">
          <Link
            to="/dashboard"
            className="rounded-full px-7 py-3 text-[0.9rem] font-semibold no-underline"
            style={{ background: "var(--brand)", color: "var(--brand-ink)" }}
          >
            Open dashboard
          </Link>
          <a
            href="https://github.com/Abimanyu-A/p4"
            target="_blank"
            rel="noreferrer"
            className="rounded-full border px-7 py-3 text-[0.9rem] font-semibold no-underline"
            style={{ borderColor: "var(--ink)", color: "var(--ink)" }}
          >
            View on GitHub
          </a>
        </div>
      </section>

      {/* Pipeline showcase */}
      <section className="border-t" style={{ borderColor: "var(--border)", background: "var(--beige-soft)" }}>
        <div className="mx-auto max-w-6xl px-6 py-20 sm:px-10 sm:py-28">
          <h2 className="font-display m-0 text-2xl font-semibold sm:text-3xl">The pipeline</h2>
          <p className="ink-secondary mt-3 max-w-xl text-[0.95rem]">
            Five decoupled stages. Each one's output is the next one's typed
            input - swappable independently.
          </p>
          <div className="mt-14 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-5">
            {STAGES.map((s) => (
              <div key={s.n} className="surface rounded-lg px-6 py-7">
                <div className="font-display mb-4 text-[0.85rem] font-semibold" style={{ color: "var(--gold)" }}>
                  {s.n}
                </div>
                <h3 className="font-display m-0 mb-2 text-lg font-semibold">{s.title}</h3>
                <p className="ink-secondary m-0 text-[0.84rem] leading-relaxed">{s.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Stats / proof */}
      <section className="mx-auto max-w-6xl px-6 py-20 sm:px-10 sm:py-28">
        <h2 className="font-display m-0 text-2xl font-semibold sm:text-3xl">
          Measured, not claimed
        </h2>
        <p className="ink-secondary mt-3 max-w-xl text-[0.95rem]">
          Computed live against a hand-labeled ground truth of real
          vulnerabilities and planted false-positive traps - not eyeballed.
        </p>
        <div className="mt-14 grid grid-cols-1 gap-8 sm:grid-cols-3">
          {STATS.map((s) => (
            <div key={s.label}>
              <div className="font-display tabular text-5xl font-semibold" style={{ color: "var(--ink)" }}>
                {s.value}
              </div>
              <div className="mt-3 text-[0.9rem] font-medium">{s.label}</div>
              <div className="ink-muted mt-1 text-[0.8rem]">{s.sub}</div>
            </div>
          ))}
        </div>
      </section>

      {/* CTA band */}
      <section style={{ background: "var(--ink)" }}>
        <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-6 px-6 py-16 sm:flex-row sm:items-center sm:px-10">
          <div>
            <h2 className="font-display m-0 text-2xl font-semibold" style={{ color: "var(--ink-ink)" }}>
              Run a scan and watch it prove itself.
            </h2>
            <p className="mt-2 text-[0.9rem]" style={{ color: "rgba(242,237,228,0.7)" }}>
              Three demo repos, real vulnerabilities, real sandboxed exploitation.
            </p>
          </div>
          <Link
            to="/dashboard"
            className="flex-none rounded-full px-7 py-3 text-[0.9rem] font-semibold no-underline"
            style={{ background: "var(--gold)", color: "var(--gold-ink)" }}
          >
            Open dashboard
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="mx-auto max-w-6xl px-6 py-10 sm:px-10">
        <div className="ink-muted flex flex-wrap items-center justify-between gap-3 text-[0.78rem]">
          <span>P4 - Proof-Driven Vulnerability Validation Platform</span>
          <p className="ink-muted">
            <b>Team:</b> CyberSquad
          </p>
        </div>
      </footer>
    </main>
  );
}
