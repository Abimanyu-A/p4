// Mirrors backend/core/severity.py — Semgrep emits INFO/WARNING/ERROR, the UI
// works in the more conventional low/medium/high/critical scale.
export type StandardSeverity = "low" | "medium" | "high" | "critical";

const SEMGREP_TO_STANDARD: Record<string, StandardSeverity> = {
  INFO: "low",
  WARNING: "medium",
  ERROR: "high",
};

const ORDER: StandardSeverity[] = ["low", "medium", "high", "critical"];

export function normalizeSeverity(raw: string): StandardSeverity {
  const upper = (raw ?? "").toUpperCase();
  if (upper in SEMGREP_TO_STANDARD) return SEMGREP_TO_STANDARD[upper];
  const lower = (raw ?? "").toLowerCase() as StandardSeverity;
  return ORDER.includes(lower) ? lower : "medium";
}

export function severityRank(raw: string): number {
  return ORDER.indexOf(normalizeSeverity(raw));
}
