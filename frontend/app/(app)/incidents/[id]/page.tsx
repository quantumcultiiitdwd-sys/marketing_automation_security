"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { Fragment, useState } from "react";
import { Badge, Card, Confirm, ErrorBox, Loading, PageHead, toast } from "@/components/ui";
import { ago, api, can, humanize, useApi, when } from "@/lib/api";

const NEXT_STATUS: Record<string, [string, string][]> = {
  open: [["investigating", "Start investigating"], ["resolved", "Resolve"], ["closed", "Close"]],
  investigating: [["mitigating", "Mitigating"], ["resolved", "Resolve"], ["closed", "Close"]],
  awaiting_approval: [["investigating", "Investigate"], ["resolved", "Resolve"]],
  mitigating: [["investigating", "Back to investigating"], ["resolved", "Resolve"]],
  resolved: [["closed", "Close"], ["open", "Reopen"]],
  closed: [["open", "Reopen"]],
};

function tone(type: string, severity: string) {
  if (type.includes("failed") || severity === "high" || severity === "critical") return "red";
  if (type.includes("duplicate") || type === "policy.decision") return "orange";
  if (type.includes("executed") || type.includes("succeeded") || type.includes("approved") || type.includes("recovered")) return "green";
  return "blue";
}

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: inc, error, loading, reload } = useApi<any>(`/incidents/${id}`, 20000);
  const [selected, setSelected] = useState<number | null>(null);
  const [comment, setComment] = useState("");
  const [execute, setExecute] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<unknown>, ok?: string) {
    setBusy(true);
    try { await fn(); if (ok) toast(ok); await reload(); } catch (e) { toast((e as Error).message); } finally { setBusy(false); }
  }

  async function exportReport() {
    const text = await api<string>(`/incidents/${id}/report`, { text: true });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
    a.download = `incident-${id.slice(0, 8)}.md`;
    a.click();
  }

  if (loading && !inc) return <Loading rows={5} />;
  if (error && !inc) return <ErrorBox error={error} onRetry={reload} />;
  if (!inc) return null;

  const rca = inc.rca ?? {};
  const hyp = selected != null ? rca.hypotheses?.find((h: any) => h.rank === selected) : null;
  const evidence = new Set<string>(hyp?.evidence_ids ?? []);
  const proposed = inc.remediations.filter((r: any) => r.status === "proposed");

  return (
    <>
      <p className="small" style={{ margin: "0 0 8px" }}><Link href="/incidents">← Incidents</Link></p>
      <PageHead title={inc.title} sub={<span className="row" style={{ gap: 8 }}>
        <Badge value={inc.severity} /><Badge value={inc.status} /><span>{humanize(inc.kind)} · detected {when(inc.detected_at)}</span>
      </span>}>
        {can("operator") && inc.status === "open" && <button className="btn primary" disabled={busy} onClick={() => run(() => api(`/incidents/${id}/acknowledge`, { body: {} }), "Acknowledged")}>Acknowledge</button>}
        {can("operator") && (
          <select className="select inline" value="" disabled={busy} aria-label="Change status"
            onChange={(e) => e.target.value && run(() => api(`/incidents/${id}`, { method: "PATCH", body: { status: e.target.value, version: inc.version } }), "Status updated")}>
            <option value="">Change status…</option>
            {(NEXT_STATUS[inc.status] ?? []).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        )}
        {can("operator") && <button className="btn" disabled={busy} onClick={() => run(() => api(`/incidents/${id}/escalate`, { body: {} }), "Escalated")}>Escalate</button>}
        {can("operator") && <button className="btn" disabled={busy} onClick={() => run(() => api(`/incidents/${id}/mute`, { body: { minutes: 60 } }), "Similar alerts muted for 1 hour")}>Mute 1h</button>}
        <button className="btn" onClick={exportReport}>Export report</button>
      </PageHead>

      <div className="split">
        <div className="stack">
          <Card title="Investigation" action={can("analyst") && <button className="btn ghost sm" disabled={busy} onClick={() => run(() => api(`/incidents/${id}/investigate`, { body: {} }), "Re-investigated")}>Re-run</button>}>
            <p style={{ margin: 0 }}>{rca.summary ?? "No investigation yet."}</p>
            {inc.resolution && <div className="banner info mt" style={{ marginBottom: 0 }}><strong>Resolution:</strong>&nbsp;{inc.resolution}</div>}
          </Card>

          <Card title="Hypotheses" action={<span className="faint">Inferred · heuristic confidence</span>}>
            <div className="stack">
              {(rca.hypotheses ?? []).map((h: any) => (
                <div key={h.rank} className={`hyp ${selected === h.rank ? "selected" : ""}`} role="button" tabIndex={0}
                  onClick={() => setSelected(selected === h.rank ? null : h.rank)} onKeyDown={(e) => e.key === "Enter" && setSelected(selected === h.rank ? null : h.rank)}>
                  <div className="spread" style={{ alignItems: "flex-start" }}>
                    <div className="row" style={{ gap: 10, alignItems: "flex-start", flexWrap: "nowrap" }}>
                      <span className="rank">{h.rank}</span>
                      <div>
                        <div className="title">{h.cause}</div>
                        <div className="small muted">{h.explanation}</div>
                      </div>
                    </div>
                    <div className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                      <Badge value={h.confidence_label} label={`${humanize(h.confidence_label)} confidence`} tone={h.confidence_label === "high" ? "blue" : ""} />
                      {h.verified ? <Badge value="verified" tone="green" /> : <Badge label="Unverified" />}
                    </div>
                  </div>
                  {h.missing_evidence.length > 0 && <div className="faint" style={{ marginTop: 8, marginLeft: 34 }}>Missing evidence: {h.missing_evidence.join("; ")}</div>}
                  {h.next_steps.length > 0 && <ul className="small" style={{ margin: "8px 0 0 34px", paddingLeft: 16 }}>{h.next_steps.map((s: string) => <li key={s}>{s}</li>)}</ul>}
                  <div className="row" style={{ marginTop: 10, marginLeft: 34 }} onClick={(e) => e.stopPropagation()}>
                    <span className="faint">{h.evidence_ids.length} evidence event{h.evidence_ids.length === 1 ? "" : "s"}{selected === h.rank ? " highlighted below" : " — select to highlight"}</span>
                    {can("analyst") && !h.feedback && h.score > 0 && (
                      <>
                        <button className="btn sm" onClick={() => run(() => api(`/incidents/${id}/feedback`, { body: { rank: h.rank, verdict: "confirmed" } }), "Marked as confirmed")}>Confirm</button>
                        <button className="btn sm" onClick={() => run(() => api(`/incidents/${id}/feedback`, { body: { rank: h.rank, verdict: "rejected" } }), "Marked as rejected")}>Reject</button>
                      </>
                    )}
                    {h.feedback && <span className="faint">{humanize(h.feedback.verdict)} by {h.feedback.by}</span>}
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card title="Timeline" action={<span className="faint">Observed facts · UTC</span>}>
            {(rca.timeline ?? []).length === 0 ? <p className="faint">No related events were found in the investigation window.</p> : (
              <ul className="timeline">
                {rca.timeline.map((t: any) => {
                  const on = evidence.has(t.event_id);
                  return (
                    <li key={t.event_id} className={hyp ? (on ? "hl" : "dim") : ""}>
                      <span className={`node ${tone(t.type, t.severity)}`} />
                      <div className="desc">{t.description}{t.is_symptom && <> <Badge label="Symptom" tone="red" /></>}</div>
                      <div className="meta">{new Date(t.at).toISOString().slice(11, 19)} · {t.type} · {t.source}{t.trace_id && <> · <span className="mono">{t.trace_id}</span></>}</div>
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>

          <Card title="Remediation" action={can("operator") && (
            <button className="btn sm" disabled={busy} onClick={() => run(() => api("/remediations/plan", { body: { incident_id: id } }), "Plan generated")}>
              {inc.remediations.length ? "Re-plan" : "Generate plan"}
            </button>
          )}>
            {inc.remediations.length === 0 ? <p className="faint">Generate a plan to see recommended containment and recovery steps. Nothing runs without your approval.</p> : (
              <ul className="list">
                {inc.remediations.map((r: any) => (
                  <li key={r.id}>
                    <div className="spread" style={{ alignItems: "flex-start" }}>
                      <div style={{ minWidth: 0 }}>
                        <div className="title">{r.step}. {r.title}</div>
                        {r.description && <div className="small muted">{r.description}</div>}
                        <div className="row" style={{ gap: 6, marginTop: 6 }}>
                          <Badge label={r.action_type ? "Automated" : "Manual"} tone={r.action_type ? "blue" : ""} />
                          {r.action_type && <Badge value={r.risk} label={`${humanize(r.risk)} risk`} />}
                          {r.reversibility !== "n/a" && <Badge value={r.reversibility} />}
                          <Badge value={r.status} />
                        </div>
                        {r.verification && <div className="faint" style={{ marginTop: 6 }}>
                          {r.verification.blocked ? `Blocked by policy: ${r.verification.reasons.map((x: any) => x.message).join("; ")}`
                            : `Verification: ${r.verification.verified ? "state confirmed" : "could not confirm — escalated"} · ${when(r.verification.checked_at)}`}
                        </div>}
                      </div>
                      {r.status === "proposed" && can("operator") && (
                        <div className="row" style={{ flexWrap: "nowrap" }}>
                          {r.action_type
                            ? <button className="btn sm primary" onClick={() => setExecute(r)}>Approve & run</button>
                            : <button className="btn sm" onClick={() => run(() => api(`/remediations/${r.id}/complete`, { body: { status: "done" } }), "Marked done")}>Mark done</button>}
                          <button className="btn sm ghost" onClick={() => run(() => api(`/remediations/${r.id}/complete`, { body: { status: "skipped" } }))}>Skip</button>
                        </div>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {proposed.length > 0 && <p className="faint mt">Automated steps re-check current state, pass through policy evaluation, and execute at most once.</p>}
          </Card>
        </div>

        <div className="stack">
          <Card title="Details">
            <dl className="kv">
              <dt>Status</dt><dd><Badge value={inc.status} /></dd>
              <dt>Owner</dt><dd>{inc.assignee_email ?? "Unassigned"}</dd>
              <dt>Detected</dt><dd>{when(inc.detected_at)}</dd>
              <dt>Last seen</dt><dd>{ago(inc.last_seen_at)}</dd>
              <dt>Occurrences</dt><dd>{inc.occurrence_count}</dd>
              {inc.resource_type && <><dt>Resource</dt><dd className="mono small">{inc.resource_type}:{inc.resource_id?.slice(0, 8)}</dd></>}
              {inc.resolved_at && <><dt>Resolved</dt><dd>{when(inc.resolved_at)}</dd></>}
            </dl>
          </Card>
          {rca.blast_radius && (
            <Card title="Blast radius">
              <dl className="kv">
                {Object.entries(rca.blast_radius).filter(([k]) => k !== "resources").map(([k, v]) => <Fragment key={k}><dt>{humanize(k)}</dt><dd>{String(v)}</dd></Fragment>)}
              </dl>
              {rca.blast_radius.resources.length > 0 && <div className="faint mt">{rca.blast_radius.resources.map((r: string) => r.split(":")[0]).join(", ")}</div>}
            </Card>
          )}
          {inc.decisions.length > 0 && (
            <Card title="Policy decisions">
              <ul className="list">
                {inc.decisions.map((d: any) => (
                  <li key={d.id}>
                    <div className="spread"><span className="mono small">{d.action_type}</span><Badge value={d.decision} /></div>
                    {d.reasons.map((r: any, i: number) => <div key={i} className="faint">{r.policy ? `${r.policy} v${r.version}: ` : ""}{r.message}</div>)}
                  </li>
                ))}
              </ul>
            </Card>
          )}
          <Card title="Detector evidence">
            <ul className="list">
              {inc.evidence.map((e: any) => (
                <li key={e.id}>
                  <div className="title small">{humanize(e.evidence_type)}</div>
                  <div className="faint">{e.data.message}</div>
                  <details className="small"><summary className="faint" style={{ cursor: "pointer" }}>Data</summary>
                    <pre className="code" style={{ marginTop: 6 }}>{JSON.stringify(e.data, null, 2)}</pre>
                  </details>
                </li>
              ))}
            </ul>
          </Card>
          <Card title="Activity">
            <ul className="list">
              {inc.activity.map((a: any) => (
                <li key={a.id}>
                  <div className="small">
                    {a.kind === "comment" ? a.body.text : a.kind === "status" ? `Status → ${humanize(a.body.to)}${a.body.note ? `: ${a.body.note}` : ""}`
                      : a.kind === "feedback" ? `${humanize(a.body.verdict)} hypothesis: ${a.body.cause}` : a.body.message ?? humanize(a.kind)}
                  </div>
                  <div className="faint">{a.actor.replace(/^user:/, "")} · {ago(a.created_at)}</div>
                </li>
              ))}
            </ul>
            {can("analyst") && (
              <form className="stack mt" onSubmit={(e) => { e.preventDefault(); if (comment.trim()) run(() => api(`/incidents/${id}/comments`, { body: { body: comment } }).then(() => setComment(""))); }}>
                <textarea className="textarea" placeholder="Add a note…" value={comment} onChange={(e) => setComment(e.target.value)} aria-label="Comment" />
                <button className="btn sm" style={{ alignSelf: "flex-end" }} disabled={!comment.trim() || busy}>Comment</button>
              </form>
            )}
          </Card>
        </div>
      </div>

      <Confirm open={!!execute} onClose={() => setExecute(null)} danger={execute?.risk === "high"} confirmLabel="Approve and run"
        title="Approve remediation"
        body={execute && (
          <>
            <p style={{ margin: 0 }}><strong>{execute.title}</strong></p>
            <p className="muted" style={{ margin: 0 }}>{execute.description}</p>
            <dl className="kv">
              <dt>Action</dt><dd className="mono small">{execute.action_type}</dd>
              <dt>Risk</dt><dd>{humanize(execute.risk)}</dd>
              <dt>Reversibility</dt><dd>{humanize(execute.reversibility)}</dd>
            </dl>
            <div className="banner warn" style={{ margin: 0 }}>This changes external state. Your identity and the time are recorded in the audit log.</div>
          </>
        )}
        onConfirm={async () => {
          const r = await api(`/remediations/${execute.id}/execute`, { body: { confirm: true } });
          toast(r.status === "verified" ? "Executed and verified" : "Executed — verification failed, escalated");
          reload();
        }} />
    </>
  );
}
