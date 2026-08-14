import type { Finding, Report } from "../types";

interface ComparisonPanelProps {
  report: Report | null;
  findings: Finding[];
}

const METRICS: Array<{ key: "precision" | "recall" | "f1"; label: string }> = [
  { key: "precision", label: "Precision" },
  { key: "recall", label: "Recall" },
  { key: "f1", label: "F1" },
];

function StatTile({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string;
  sub: string;
  accent?: string;
}) {
  return (
    <div className="surface rounded-lg px-4 py-3.5">
      <div className="ink-muted mb-1.5 text-[0.72rem] tracking-wide uppercase">{label}</div>
      <div className="font-display tabular text-2xl font-semibold" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      <div className="ink-secondary mt-1 text-[0.74rem]">{sub}</div>
    </div>
  );
}

export function ComparisonPanel({ report, findings }: ComparisonPanelProps) {
  const confirmed = findings.filter((f) => f.verdict === "confirmed").length;
  const suppression = report?.false_positive_suppression_rate;

  return (
    <section className="grid grid-cols-1 gap-3 lg:grid-cols-[2fr_1fr_1fr_1fr]">
      <div className="surface rounded-lg px-5 py-4">
        <div className="mb-1 flex items-baseline justify-between">
          <span className="font-display text-sm font-semibold">Baseline vs. P4 (post-validate)</span>
        </div>
        <div className="mb-3 flex gap-4 text-[0.74rem]">
          <span className="ink-secondary flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: "var(--chart-baseline)" }} />
            Baseline (raw scan)
          </span>
          <span className="ink-secondary flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: "var(--chart-pipeline)" }} />
            P4 (LLM-validated)
          </span>
        </div>

        {!report ? (
          <p className="ink-muted py-3 text-[0.82rem]">Run a scan to see the comparison.</p>
        ) : (
          <>
            <div className="flex flex-col gap-3">
              {METRICS.map(({ key, label }) => {
                const baselineVal = Math.round(report.baseline[key] * 100);
                const pipelineVal = Math.round(report.pipeline[key] * 100);
                return (
                  <div key={key} className="grid grid-cols-[64px_1fr_40px] items-center gap-3">
                    <div className="text-[0.78rem] font-medium">{label}</div>
                    <div className="flex flex-col gap-1" role="img" aria-label={`${label}: baseline ${baselineVal}%, P4 ${pipelineVal}%`}>
                      <div className="h-2 rounded-full" style={{ background: "var(--chart-baseline-wash)" }}>
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{ width: `${baselineVal}%`, background: "var(--chart-baseline)" }}
                        />
                      </div>
                      <div className="h-2 rounded-full" style={{ background: "var(--chart-pipeline-wash)" }}>
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{ width: `${pipelineVal}%`, background: "var(--chart-pipeline)" }}
                        />
                      </div>
                    </div>
                    <div className="tabular text-right text-[0.8rem] font-semibold">{pipelineVal}%</div>
                  </div>
                );
              })}
            </div>
            <table className="sr-only">
              <caption>Baseline vs. P4 precision, recall, and F1</caption>
              <thead>
                <tr>
                  <th>Metric</th>
                  <th>Baseline</th>
                  <th>P4</th>
                </tr>
              </thead>
              <tbody>
                {METRICS.map(({ key, label }) => (
                  <tr key={key}>
                    <td>{label}</td>
                    <td>{Math.round(report.baseline[key] * 100)}%</td>
                    <td>{Math.round(report.pipeline[key] * 100)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>

      <StatTile
        label="FP suppression"
        value={suppression == null ? "—" : `${Math.round(suppression * 100)}%`}
        sub={
          report
            ? `${report.baseline.false_positives} → ${report.pipeline.false_positives} false positives`
            : "false positives cleared by Validate"
        }
        accent="var(--status-good-text)"
      />
      <StatTile
        label="Cross-repo dedup"
        value={report ? String(report.cross_repo_dedup_groups) : "—"}
        sub="vulnerability groups merged across repos"
        accent="var(--accent)"
      />
      <StatTile
        label="Confirmed / total"
        value={findings.length ? `${confirmed} / ${findings.length}` : "—"}
        sub={report ? `${report.answer_key_coverage} matched to ground truth` : "candidate findings triaged"}
      />
    </section>
  );
}
