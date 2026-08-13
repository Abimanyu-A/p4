import { useState } from "react";
import type { DefectDojoResult } from "../types";

interface RemediationPanelProps {
  canSync: boolean;
  onSync: () => Promise<DefectDojoResult>;
  onError: (message: string) => void;
}

export function RemediationPanel({ canSync, onSync, onError }: RemediationPanelProps) {
  const [status, setStatus] = useState(
    "Formats confirmed findings as a Generic Finding Import payload.",
  );
  const [syncing, setSyncing] = useState(false);

  const handleSync = async () => {
    if (!canSync) {
      onError("Run a scan first");
      return;
    }
    setSyncing(true);
    try {
      const result = await onSync();
      setStatus(
        result.synced
          ? `Synced ${result.count} findings to ${result.target}`
          : `${result.note} (${result.would_sync_count} findings ready to sync)`,
      );
    } catch (e) {
      onError(`Sync failed: ${(e as Error).message}`);
    } finally {
      setSyncing(false);
    }
  };

  return (
    <section>
      <h2 className="font-display mb-3 text-base font-semibold">Remediation sync</h2>
      <div className="surface flex items-center justify-between gap-3 rounded-lg px-5 py-4">
        <div>
          <div className="text-[0.86rem] font-medium">DefectDojo import</div>
          <div className="ink-secondary text-[0.78rem]">{status}</div>
        </div>
        <button
          type="button"
          onClick={handleSync}
          disabled={syncing}
          className="surface-raised ink-primary cursor-pointer rounded-md px-3.5 py-2 text-[0.8rem] font-semibold disabled:cursor-not-allowed disabled:opacity-60"
        >
          {syncing ? "Syncing…" : "Sync to DefectDojo"}
        </button>
      </div>
    </section>
  );
}
