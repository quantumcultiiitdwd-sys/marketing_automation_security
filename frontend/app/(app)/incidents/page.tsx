"use client";

import Link from "next/link";
import { useState } from "react";
import { Badge, Card, Empty, ErrorBox, Icons, Loading, PageHead, Segmented } from "@/components/ui";
import { ago, humanize, useApi } from "@/lib/api";

export default function Incidents() {
  const [view, setView] = useState("active");
  const [severity, setSeverity] = useState("");
  const q = new URLSearchParams();
  if (view === "active") q.set("active", "true");
  if (view === "resolved") q.set("status", "resolved");
  if (severity) q.set("severity", severity);
  const { data, error, loading, reload } = useApi<any[]>(`/incidents?${q}`, 15000);

  return (
    <>
      <PageHead title="Incidents" sub="Detected failures, anomalies and blocked actions, with evidence-backed investigations.">
        <select className="select inline" value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">All severities</option>
          {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
        </select>
        <Segmented value={view} onChange={setView} options={[["active", "Active"], ["resolved", "Resolved"], ["all", "All"]]} />
      </PageHead>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data && <Loading />}
      {data && (
        <Card flush>
          {data.length === 0 ? <Empty title={view === "active" ? "No active incidents" : "No incidents"} icon={Icons.incidents}>Nothing needs your attention.</Empty> : (
            <ul className="list" style={{ padding: "8px 20px" }}>
              {data.map((i) => (
                <li key={i.id} style={{ padding: "14px 0" }}>
                  <Link className="list-link" href={`/incidents/${i.id}`}>
                    <div className="spread" style={{ alignItems: "flex-start" }}>
                      <div style={{ minWidth: 0 }}>
                        <div className="row" style={{ gap: 8 }}><Badge value={i.severity} /><span className="title">{i.title}</span></div>
                        {i.top_cause && <div className="small muted" style={{ marginTop: 4 }}>Likely: {i.top_cause} <span className="faint">(unverified)</span></div>}
                        <div className="faint" style={{ marginTop: 2 }}>
                          {humanize(i.kind)} · detected {ago(i.detected_at)}{i.occurrence_count > 1 && ` · ${i.occurrence_count} occurrences`}
                        </div>
                      </div>
                      <Badge value={i.status} />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
    </>
  );
}
