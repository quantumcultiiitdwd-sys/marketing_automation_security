"use client";

import Link from "next/link";
import { useState } from "react";
import { Badge, Card, Dot, Empty, ErrorBox, Icons, Loading, PageHead, Segmented, toast } from "@/components/ui";
import { ago, api, can, humanize, useApi } from "@/lib/api";

const SEV_TONE: Record<string, string> = { critical: "red", high: "orange", medium: "yellow", low: "blue" };

export default function Overview() {
  const [days, setDays] = useState("7");
  const { data: d, error, loading, reload } = useApi<any>(`/dashboard/summary?days=${days}`, 15000);
  const [seeding, setSeeding] = useState(false);

  async function seed() {
    setSeeding(true);
    try {
      await api("/demo/seed", { body: {} });
      toast("Sandbox data loaded");
      reload();
    } catch (e) {
      toast((e as Error).message);
    } finally {
      setSeeding(false);
    }
  }

  return (
    <>
      <PageHead title="Overview" sub={d ? `${d.organization.name} · updated ${ago(d.generated_at)}` : " "}>
        <Segmented value={days} onChange={setDays} options={[["1", "24 hours"], ["7", "7 days"], ["30", "30 days"]]} />
      </PageHead>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !d && <Loading rows={4} />}
      {d && (
        <>
          {d.organization.kill_switch && (
            <div className="banner danger"><strong>Kill switch engaged.</strong> Every gateway action is being denied. <Link href="/settings">Manage</Link></div>
          )}
          {d.integrations.total === 0 ? (
            <Card>
              <Empty title="Connect your first integration" icon={Icons.integrations}>
                <p>Connect n8n or Google Ads, or load a sandbox to explore every scenario safely.</p>
                <div className="row" style={{ justifyContent: "center", marginTop: 16 }}>
                  <Link className="btn primary" href="/integrations">Add integration</Link>
                  {can("admin") && <button className="btn" onClick={seed} disabled={seeding}>{seeding ? "Loading…" : "Load sandbox data"}</button>}
                </div>
              </Empty>
            </Card>
          ) : (
            <>
              <div className="grid grid-stats">
                <Stat label="Open incidents" value={d.incidents.open} tone={d.incidents.by_severity.critical ? "red" : d.incidents.open ? "orange" : "green"}
                  hint={Object.entries(d.incidents.by_severity).filter(([, n]) => (n as number) > 0).map(([s, n]) => `${n} ${s}`).join(" · ") || "All clear"} href="/incidents" />
                <Stat label="Actions blocked" value={d.protection.actions_blocked} hint={`${d.protection.actions_executed} executed safely`} href="/policies" />
                <Stat label="Duplicates suppressed" value={d.protection.duplicates_suppressed} hint="Same idempotency key" />
                <Stat label="Awaiting approval" value={d.protection.pending_approvals} tone={d.protection.pending_approvals ? "purple" : undefined} href="/approvals" />
                <Stat label="Monitored workflows" value={d.workflows.monitored}
                  hint={Object.entries(d.workflows.health).map(([h, n]) => `${n} ${h}`).join(" · ") || "—"} href="/workflows" />
                <Stat label="Integrations" value={`${d.integrations.connected}/${d.integrations.total}`} hint="connected" href="/integrations" />
              </div>

              <div className="grid grid-2 mt">
                <Card title="Open incidents" action={<Link href="/incidents" className="small">View all</Link>}>
                  {d.incidents.recent.length === 0 ? <Empty title="No open incidents">Everything is operating normally.</Empty> : (
                    <ul className="list">
                      {d.incidents.recent.map((i: any) => (
                        <li key={i.id}>
                          <Link className="list-link" href={`/incidents/${i.id}`}>
                            <div className="line">
                              <Dot tone={SEV_TONE[i.severity]} />
                              <div className="grow">
                                <div className="title">{i.title}</div>
                                <div className="faint">{humanize(i.kind)} · {ago(i.last_seen_at)}{i.occurrence_count > 1 && ` · ${i.occurrence_count}×`}</div>
                              </div>
                              <Badge value={i.status} />
                            </div>
                          </Link>
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>
                <Card title="Integration health" action={<Link href="/integrations" className="small">Manage</Link>}>
                  <ul className="list">
                    {d.integrations.items.map((i: any) => (
                      <li key={i.id} className="spread">
                        <div>
                          <div className="row" style={{ gap: 8 }}><Dot tone={i.status === "connected" ? "green" : "red"} /><span className="title">{i.name}</span></div>
                          <div className="faint" style={{ marginLeft: 18 }}>
                            {i.enforcement === "observe_only" ? "Observe only — cannot block actions" : "Gateway enforcement"} · checked {ago(i.last_check_at)}
                          </div>
                          {i.last_error && <div className="small" style={{ color: "var(--red)", marginLeft: 18 }}>{i.last_error}</div>}
                        </div>
                        <Badge value={i.mode} />
                      </li>
                    ))}
                  </ul>
                </Card>
                <Card title="Recent policy decisions" action={<Link href="/policies" className="small">Policies</Link>}>
                  {d.policy_violations.recent.length === 0 ? <Empty title="No violations" icon={Icons.policies}>No guarded action was blocked in this window.</Empty> : (
                    <ul className="list">
                      {d.policy_violations.recent.map((p: any) => (
                        <li key={p.id}>
                          <div className="spread"><span className="title mono">{p.action_type}</span><Badge value={p.decision} label={p.decision === "DENY" ? "Blocked" : "Needs approval"} /></div>
                          <div className="faint">{p.reasons.filter((r: any) => r.outcome !== "ALLOW").map((r: any) => r.message).join("; ")} · {ago(p.created_at)}</div>
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>
                <Card title="Recent traces">
                  {d.recent_traces.length === 0 ? <Empty title="No traces yet" icon={Icons.workflows} /> : (
                    <ul className="list">
                      {d.recent_traces.map((t: any) => (
                        <li key={t.trace_id} className="spread">
                          <div style={{ minWidth: 0 }}>
                            <div className="mono" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{t.trace_id}</div>
                            <div className="faint">{t.events} events · {humanize(t.root)} · {ago(t.last_event_at)}</div>
                          </div>
                          <Badge value={t.status} tone={t.status === "ok" ? "green" : "red"} label={t.status === "ok" ? "OK" : humanize(t.status)} />
                        </li>
                      ))}
                    </ul>
                  )}
                </Card>
              </div>
              {d.spend_anomalies.length > 0 && (
                <Card title="Spend anomalies" className="mt">
                  <ul className="list">
                    {d.spend_anomalies.map((i: any) => (
                      <li key={i.id}><Link href={`/incidents/${i.id}`}>{i.title}</Link> <span className="faint">· {ago(i.detected_at)} · based on provider metrics that may be delayed</span></li>
                    ))}
                  </ul>
                </Card>
              )}
            </>
          )}
        </>
      )}
    </>
  );
}

function Stat({ label, value, hint, tone, href }: { label: string; value: React.ReactNode; hint?: string; tone?: string; href?: string }) {
  const body = (
    <div className="card stat" style={{ height: "100%" }}>
      <div className="label row" style={{ gap: 6 }}>{tone && <Dot tone={tone} />}{label}</div>
      <div className="value">{value}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
  return href ? <Link href={href} style={{ color: "inherit", textDecoration: "none" }}>{body}</Link> : body;
}
