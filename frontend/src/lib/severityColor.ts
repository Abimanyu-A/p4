import { normalizeSeverity } from "./severity";

export function severityColor(rawSeverity: string): string {
  switch (normalizeSeverity(rawSeverity)) {
    case "critical":
      return "var(--status-critical)";
    case "high":
      return "var(--status-serious)";
    case "medium":
      return "var(--status-warning)";
    default:
      return "var(--ink-muted)";
  }
}
