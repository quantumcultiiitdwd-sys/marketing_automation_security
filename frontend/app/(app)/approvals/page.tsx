"use client";

import { useState } from "react";
import { Badge, Card, Confirm, Empty, ErrorBox, Icons, Loading, PageHead, Segmented, toast } from "@/components/ui";
import { ago, api, can, humanize, money, useApi, when } from "@/lib/api";

export default function Approvals() {
  const [view, setView] = useState("pending");
  const { data, error, loading, reload } = useApi<any[]>(`/approvals${view === "pending" ? "?status=pending" : ""}`, 15000);
  const [decide, setDecide] = useState<{ a: any; approve: boolean } | null>(null);
  const [note, setNote] = useState("");

  return (
    <>
      <PageHead title="Approvals" sub="Agent actions that exceeded a policy and are waiting for a human decision.">
        <Segmented value={view} onChange={setView} options={[["pending", "Pending"], ["all", "History"]]} />
      </PageHead>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data && <Loading />}
      {data && data.length === 0 && <Card><Empty title={view === "pending" ? "Nothing waiting" : "No approvals yet"} icon={Icons.approvals}>Requests that need approval will appear here.</Empty></Card>}
      <div className="stack">
        {data?.map((a) => {
          const p = a.action.parameters;
          const prior = a.action.prior_state ?? {};
          return (
            <Card key={a.id}>
              <div className="spread" style={{ alignItems: "flex-start" }}>
                <div>
                  <div className="mono">{a.action.action_type}</div>
                  <div className="faint">Requested by {a.requested_by.replace(/^agent:/, "agent ")} · {ago(a.created_at)} · needs {a.required_role} or higher</div>
                </div>
                <Badge value={a.status} />
              </div>
              {p.proposed_daily_budget != null && (
                <div className="row mt" style={{ fontSize: 22, fontWeight: 600, letterSpacing: "-0.02em" }}>
                  <span className="muted">{money(prior.daily_budget, prior.currency)}</span><span className="muted">→</span><span>{money(p.proposed_daily_budget, prior.currency)}</span>
                </div>
              )}
              {p.recipients && <p className="small">{p.recipients.length} recipients · “{p.subject}”</p>}
              <ul className="small" style={{ paddingLeft: 18, margin: "12px 0 0" }}>
                {a.reasons.filter((r: any) => r.outcome !== "ALLOW").map((r: any, i: number) => <li key={i}>{r.message} <span className="faint">({r.policy} v{r.version})</span></li>)}
              </ul>
              {a.status === "pending" && can("operator") && (
                <div className="row mt">
                  <button className="btn primary" onClick={() => { setNote(""); setDecide({ a, approve: true }); }}>Approve</button>
                  <button className="btn danger" onClick={() => { setNote(""); setDecide({ a, approve: false }); }}>Reject</button>
                </div>
              )}
              {a.status !== "pending" && (
                <p className="faint mt">{humanize(a.status)} {when(a.decided_at)}{a.note && ` — “${a.note}”`} · action {humanize(a.action.status).toLowerCase()}
                  {a.action.result?.error === "stale_state" && " (budget changed since the request, so it was not applied)"}</p>
              )}
            </Card>
          );
        })}
      </div>
      <Confirm open={!!decide} onClose={() => setDecide(null)} danger={!decide?.approve} confirmLabel={decide?.approve ? "Approve & execute" : "Reject"}
        title={decide?.approve ? "Approve this action?" : "Reject this action?"}
        body={<>
          <p className="muted" style={{ margin: 0 }}>{decide?.approve ? "Current state is re-checked first. If it changed since the request, nothing is executed." : "The agent's request will not be executed."}</p>
          <textarea className="textarea" placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Note" />
        </>}
        onConfirm={async () => {
          const r = await api(`/approvals/${decide!.a.id}/${decide!.approve ? "approve" : "reject"}`, { body: { note: note || null } });
          toast(r.status === "executed" ? "Approved and executed" : r.status === "rejected" && decide!.approve ? "Not executed: state changed" : `Request ${r.approval}`);
          reload();
        }} />
    </>
  );
}
