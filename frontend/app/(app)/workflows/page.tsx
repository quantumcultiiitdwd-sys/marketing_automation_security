"use client";

import { useState } from "react";
import { Badge, Card, Empty, ErrorBox, Icons, Loading, PageHead, Sheet, Switch, toast } from "@/components/ui";
import { ago, api, can, humanize, useApi, when } from "@/lib/api";

const INTERVALS: [string, string][] = [["", "No schedule"], ["5", "5 min"], ["15", "15 min"], ["60", "1 hour"], ["360", "6 hours"], ["1440", "Daily"]];

export default function Workflows() {
  const { data, error, loading, reload } = useApi<any[]>("/workflows", 20000);
  const [open, setOpen] = useState<string | null>(null);

  async function update(id: string, body: any) {
    try { await api(`/workflows/${id}`, { method: "PATCH", body }); reload(); } catch (e) { toast((e as Error).message); }
  }

  return (
    <>
      <PageHead title="Workflows" sub="Execution health across connected automation platforms. Set a schedule to detect silent failures." />
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data && <Loading />}
      {data && (
        <Card flush>
          {data.length === 0 ? <Empty title="No workflows discovered" icon={Icons.workflows}>Workflows appear after the first sync or telemetry event.</Empty> : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Workflow</th><th>Health</th><th>Success (24h)</th><th>Runs</th><th>Last run</th><th>Expected every</th><th>Monitored</th></tr></thead>
                <tbody>
                  {data.map((w) => (
                    <tr key={w.id} className="clickable" onClick={() => setOpen(w.id)}>
                      <td><div className="title">{w.name}</div><div className="faint mono">{w.external_id}</div></td>
                      <td><Badge value={w.health} /></td>
                      <td>{w.success_rate_24h == null ? "—" : `${w.success_rate_24h}%`}</td>
                      <td>{w.executions_24h}{w.failures_24h > 0 && <span style={{ color: "var(--red)" }}> · {w.failures_24h} failed</span>}</td>
                      <td>{ago(w.last_execution_at)}</td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <select className="select inline" disabled={!can("operator")} value={w.expected_interval_minutes ?? ""} aria-label="Expected interval"
                          onChange={(e) => update(w.id, { expected_interval_minutes: e.target.value ? Number(e.target.value) : null })}>
                          {INTERVALS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                          {w.expected_interval_minutes && !INTERVALS.some(([v]) => v === String(w.expected_interval_minutes)) && <option value={w.expected_interval_minutes}>{w.expected_interval_minutes} min</option>}
                        </select>
                      </td>
                      <td onClick={(e) => e.stopPropagation()}><Switch label="Monitored" on={w.monitored} disabled={!can("operator")} onChange={(v) => update(w.id, { monitored: v })} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
      <WorkflowSheet id={open} onClose={() => setOpen(null)} />
    </>
  );
}

function WorkflowSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data } = useApi<any>(id ? `/workflows/${id}` : null);
  return (
    <Sheet open={!!id} onClose={onClose} title={data?.name ?? "Workflow"} wide>
      {!data ? <Loading /> : (
        <div className="stack">
          <dl className="kv">
            <dt>Status</dt><dd><Badge value={data.status} /> <Badge value={data.health} /></dd>
            <dt>Version</dt><dd className="mono">{data.version}</dd>
            <dt>Last run</dt><dd>{when(data.last_execution_at)}</dd>
            <dt>Config</dt><dd><code>{JSON.stringify(data.config)}</code></dd>
          </dl>
          <h3 className="mt">Recent events</h3>
          <ul className="list">
            {data.recent_events.map((e: any) => (
              <li key={e.id} className="spread">
                <div>
                  <div className="title">{humanize(e.event_type.replace("workflow.", ""))}</div>
                  <div className="faint">{e.payload.error_message ?? e.payload.execution_id ?? ""}{e.payload.duration_ms ? ` · ${e.payload.duration_ms} ms` : ""}</div>
                </div>
                <span className="faint">{when(e.occurred_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Sheet>
  );
}
