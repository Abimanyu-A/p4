import { useCallback, useEffect, useState } from "react";
import { Header } from "./components/Header";
import { Stepper } from "./components/Stepper";
import { ComparisonPanel } from "./components/ComparisonPanel";
import { FindingsList } from "./components/FindingsList";
import { RemediationPanel } from "./components/RemediationPanel";
import { Toast } from "./components/Toast";
import { useTheme } from "./hooks/useTheme";
import { useToast } from "./hooks/useToast";
import { useScanRun } from "./hooks/useScanRun";
import { api } from "./lib/api";
import type { Finding } from "./types";

export default function App() {
  const { theme, toggle } = useTheme();
  const { message, showToast } = useToast();
  const { run, findings, report, starting, running, startScan, applyApprovedFinding } =
    useScanRun(showToast);

  const [repos, setRepos] = useState<string[]>([]);
  const [selectedRepos, setSelectedRepos] = useState<Set<string>>(new Set());

  useEffect(() => {
    api
      .listRepos()
      .then(({ repos: names }) => {
        setRepos(names);
        setSelectedRepos(new Set(names));
      })
      .catch((e: Error) => showToast(`Could not load repos: ${e.message}`));
  }, [showToast]);

  const toggleRepo = useCallback((name: string) => {
    setSelectedRepos((current) => {
      const next = new Set(current);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }, []);

  const handleRunScan = useCallback(() => {
    const selected = Array.from(selectedRepos);
    if (!selected.length) {
      showToast("Select at least one repo");
      return;
    }
    startScan(selected);
  }, [selectedRepos, showToast, startScan]);

  const handleApprove = useCallback(
    async (finding: Finding) => {
      try {
        const updated = await api.approveFinding(finding.id);
        applyApprovedFinding(updated);
        showToast("Fix approved and generated");
      } catch (e) {
        showToast(`Approval failed: ${(e as Error).message}`);
      }
    },
    [applyApprovedFinding, showToast],
  );

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-5 px-4 py-6 sm:px-6">
      <Header
        repos={repos}
        selectedRepos={selectedRepos}
        onToggleRepo={toggleRepo}
        onRunScan={handleRunScan}
        running={running}
        starting={starting}
        theme={theme}
        onToggleTheme={toggle}
      />
      <Stepper run={run} findings={findings} />
      <ComparisonPanel report={report} findings={findings} />
      <FindingsList findings={findings} onApprove={handleApprove} />
      {run && (
        <RemediationPanel
          canSync={Boolean(run)}
          onSync={() => api.syncDefectDojo(run.id)}
          onError={showToast}
        />
      )}
      <Toast message={message} />
    </div>
  );
}
