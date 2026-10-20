"use client";

import { useState } from "react";
import { Badge, Card, Empty, ErrorBox, Icons, Loading, PageHead, toast } from "@/components/ui";
import { api, can, useApi, when } from "@/lib/api";

export default function Audit() {
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(0);
  const { data, error, loading, reload } = useApi<any>(can("analyst") ? `/audit?limit=50&offset=${page * 50}${filter ? `&action=${filter}` : ""}` : null);
  const [chain, setChain] = useState<any>(null);

  if (!can("analyst")) return <><PageHead title="Audit" /><Card><Empty title="Analyst role required" icon={Icons.audit} /></Card></>;

  return (
    <>
      <PageHead title="Audit" sub="Append-only, hash-chained record of policy decisions, approvals, changes and external mutations.">
        <select className="select inline" value={filter} onChange={(e) => { setFilter(e.target.value); setPage(0); }} aria-label="Filter">
          <option value="">All events</option>
          <option value="action">Actions</option>
          <option value="approval">Approvals</option>
          <option value="policy">Policies</option>
          <option value="remediation">Remediation</option>
          <option value="incident">Incidents</option>
          <option value="integration">Integrations</option>
          <option value="member">Members</option>
        </select>
        <button className="btn" onClick={async () => { const r = await api("/audit/verify"); setChain(r); toast(r.valid ? "Audit chain intact" : "Audit chain broken"); }}>Verify integrity</button>
      </PageHead>
      {chain && (
        <div className={`banner ${chain.valid ? "info" : "danger"}`}>
          {chain.valid ? `All ${chain.records} records verified — no gaps or modifications.` : `Chain broken at record #${chain.broken_at_seq}.`}
        </div>
      )}
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data && <Loading />}
      {data && (
        <Card flush>
          {data.items.length === 0 ? <Empty title="No audit records" icon={Icons.audit} /> : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Details</th></tr></thead>
                <tbody>
                  {data.items.map((r: any) => (
                    <tr key={r.seq}>
                      <td className="faint">{r.seq}</td>
                      <td style={{ whiteSpace: "nowrap" }}>{when(r.created_at)}</td>
                      <td className="small">{r.actor}</td>
                      <td><Badge label={r.action} tone={r.action.includes("denied") || r.action.includes("failed") || r.action.includes("revoked") ? "red" : r.action.includes("executed") || r.action.includes("approved") ? "green" : ""} /></td>
                      <td className="mono small">{r.resource.length > 32 ? r.resource.slice(0, 32) + "…" : r.resource}</td>
                      <td><details><summary className="faint" style={{ cursor: "pointer" }}>View</summary><pre className="code" style={{ maxWidth: 380 }}>{JSON.stringify(r.details, null, 2)}</pre></details></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
      {data && data.total > 50 && (
        <div className="row mt" style={{ justifyContent: "center" }}>
          <button className="btn sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
          <span className="faint">Page {page + 1} of {Math.ceil(data.total / 50)}</span>
          <button className="btn sm" disabled={(page + 1) * 50 >= data.total} onClick={() => setPage(page + 1)}>Next</button>
        </div>
      )}
    </>
  );
}
