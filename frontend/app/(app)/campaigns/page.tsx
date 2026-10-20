"use client";

import { useState } from "react";
import { Badge, Card, Empty, ErrorBox, Icons, Loading, PageHead, Sheet, Sparkline } from "@/components/ui";
import { ago, humanize, money, useApi, when } from "@/lib/api";

export default function Campaigns() {
  const { data, error, loading, reload } = useApi<any[]>("/campaigns", 30000);
  const [open, setOpen] = useState<string | null>(null);

  return (
    <>
      <PageHead title="Campaigns" sub="Spend against budget, from provider metrics. Advertising data can be delayed or revised — alerts are not real-time prevention." />
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data && <Loading />}
      {data && data.length === 0 && <Card><Empty title="No campaigns" icon={Icons.campaigns}>Connect Google Ads to monitor spend.</Empty></Card>}
      <div className="grid grid-3">
        {data?.map((c) => {
          const pct = c.daily_budget ? (c.spend_today / c.daily_budget) * 100 : 0;
          return (
            <button key={c.id} className="card" style={{ textAlign: "left", border: 0, cursor: "pointer" }} onClick={() => setOpen(c.id)}>
              <div className="spread" style={{ alignItems: "flex-start" }}>
                <div style={{ minWidth: 0 }}>
                  <div className="title">{c.name}</div>
                  <div className="faint">{c.currency} · {c.timezone}</div>
                </div>
                <Badge value={c.status} />
              </div>
              <div className="mt"><Sparkline values={c.series.map((p: any) => p.spend)} highlightLast /></div>
              <div className="spread mt small">
                <span><strong>{money(c.spend_today, c.currency)}</strong> <span className="muted">today</span></span>
                <span className="muted">of {money(c.daily_budget, c.currency)}</span>
              </div>
              <div className={`progress mt ${pct > 100 ? "over" : ""}`} style={{ marginTop: 8 }}><div style={{ width: `${Math.min(pct, 100)}%` }} /></div>
              <div className="faint mt" style={{ marginTop: 10 }}>
                <Badge value={c.freshness.label} label={`Metrics ${c.freshness.label}`} /> as of {ago(c.freshness.metrics_as_of)}
              </div>
            </button>
          );
        })}
      </div>
      <CampaignSheet id={open} onClose={() => setOpen(null)} />
    </>
  );
}

function CampaignSheet({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { data } = useApi<any>(id ? `/campaigns/${id}` : null);
  return (
    <Sheet open={!!id} onClose={onClose} title={data?.name ?? "Campaign"} wide>
      {!data ? <Loading /> : (
        <div className="stack">
          <div>
            <div className="faint">Hourly spend, last 7 days ({data.currency})</div>
            <Sparkline values={data.series.map((p: any) => p.spend)} height={120} highlightLast />
          </div>
          <dl className="kv">
            <dt>Daily budget</dt><dd>{money(data.daily_budget, data.currency)}</dd>
            <dt>Spend today ({data.timezone})</dt><dd>{money(data.spend_today, data.currency)}</dd>
            <dt>Metrics as of</dt><dd>{when(data.freshness.metrics_as_of)} ({data.freshness.label})</dd>
            <dt>Provider ID</dt><dd className="mono">{data.external_id}</dd>
          </dl>
          <h3 className="mt">Gateway actions</h3>
          {data.actions.length === 0 ? <p className="faint">No actions requested through the gateway.</p> : (
            <ul className="list">
              {data.actions.map((a: any) => (
                <li key={a.id} className="spread">
                  <div>
                    <div className="mono small">{a.action_type}</div>
                    <div className="faint">{a.parameters.proposed_daily_budget != null && `→ ${money(a.parameters.proposed_daily_budget, data.currency)} · `}{when(a.created_at)}</div>
                  </div>
                  <Badge value={a.status} label={humanize(a.status)} />
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Sheet>
  );
}
