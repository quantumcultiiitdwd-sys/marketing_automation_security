"use client";

import { useState } from "react";
import { Badge, Card, Empty, ErrorBox, Field, Icons, Loading, PageHead, Sheet, Switch, toast } from "@/components/ui";
import { ago, api, can, humanize, money, useApi } from "@/lib/api";

const ACTIONS = ["ads.campaign.update_budget", "ads.campaign.pause", "ads.campaign.enable", "outreach.email.send", "n8n.workflow.deactivate", "n8n.workflow.activate"];

function summarize(rules: Record<string, any>) {
  return Object.entries(rules).map(([k, v]) => `${humanize(k)}: ${Array.isArray(v) ? v.join(", ") || "none" : v}`).join(" · ");
}

export default function Policies() {
  const { data, error, loading, reload } = useApi<any[]>("/policies");
  const templates = useApi<Record<string, any>>("/policies/templates");
  const decisions = useApi<any[]>("/policies/decisions?limit=20", 20000);
  const [editing, setEditing] = useState<any>(null);

  async function toggle(p: any, on: boolean) {
    try {
      await api(`/policies/${p.versions[0].id}/${on ? "activate" : "deactivate"}`, { body: {} });
      toast(on ? `Activated v${p.versions[0].version}` : "Policy deactivated");
      reload();
    } catch (e) { toast((e as Error).message); }
  }

  return (
    <>
      <PageHead title="Policies" sub="Deterministic guardrails evaluated before every gateway action. Every change creates a new immutable version.">
        {can("admin") && <button className="btn primary" onClick={() => setEditing({ template: "budget_protection", rules: {}, name: "" })}>New policy</button>}
      </PageHead>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data && <Loading />}
      {data && data.length === 0 && <Card><Empty title="No policies" icon={Icons.policies}>Without policies, permitted agents act without limits. Unknown actions are still denied.</Empty></Card>}
      <div className="grid grid-2">
        {data?.map((p) => (
          <Card key={p.key}>
            <div className="spread" style={{ alignItems: "flex-start" }}>
              <div>
                <h2 style={{ margin: 0, fontSize: 17 }}>{p.active?.name ?? p.name}</h2>
                <div className="faint">{templates.data?.[p.template]?.name ?? p.template} · <span className="mono">{p.key}</span></div>
              </div>
              <div className="row" style={{ gap: 8 }}>
                {p.active ? <Badge label={`v${p.active.version} active`} tone="green" /> : <Badge label="Inactive" />}
                <Switch label="Active" on={!!p.active} disabled={!can("admin")} onChange={(v) => toggle(p, v)} />
              </div>
            </div>
            <p className="small muted">{summarize((p.active ?? p.versions[0]).rules)}</p>
            <div className="spread">
              <span className="faint">{p.decisions_7d} decisions in 7 days · {p.versions.length} version{p.versions.length > 1 ? "s" : ""}</span>
              {can("admin") && <button className="btn sm" onClick={() => setEditing({ key: p.key, template: p.template, name: (p.active ?? p.versions[0]).name, rules: (p.active ?? p.versions[0]).rules })}>Edit</button>}
            </div>
            {p.versions.length > 1 && (
              <details className="mt small">
                <summary className="faint" style={{ cursor: "pointer" }}>Version history</summary>
                <ul className="list mt">
                  {p.versions.map((v: any) => (
                    <li key={v.id} className="spread">
                      <span>v{v.version} · <span className="faint">{ago(v.created_at)}</span></span>
                      {v.active ? <Badge value="active" /> : can("admin") && <button className="btn sm ghost" onClick={async () => { await api(`/policies/${v.id}/activate`, { body: {} }); toast(`Rolled back to v${v.version}`); reload(); }}>Activate</button>}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </Card>
        ))}
      </div>

      <div className="grid grid-2 mt">
        <Simulator />
        <Card title="Decision history">
          {decisions.data?.length === 0 && <p className="faint">No decisions yet.</p>}
          <ul className="list">
            {decisions.data?.map((d) => (
              <li key={d.id}>
                <div className="spread"><span className="mono small">{d.action_type}</span><Badge value={d.decision} /></div>
                <div className="faint">{d.reasons.map((r: any) => r.message).join("; ")} · {ago(d.created_at)}</div>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      {editing && templates.data && <PolicyEditor initial={editing} templates={templates.data} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); reload(); }} />}
    </>
  );
}

function PolicyEditor({ initial, templates, onClose, onSaved }: { initial: any; templates: Record<string, any>; onClose: () => void; onSaved: () => void }) {
  const [template, setTemplate] = useState<string>(initial.template);
  const [name, setName] = useState<string>(initial.name || templates[initial.template].name);
  const [rules, setRules] = useState<Record<string, any>>({ ...templates[initial.template].defaults, ...initial.rules });
  const [err, setErr] = useState<string | null>(null);
  const t = templates[template];
  const isNew = !initial.key;

  function setRule(k: string, v: any) { setRules({ ...rules, [k]: v }); }

  async function save() {
    setErr(null);
    try {
      await api("/policies", { body: { key: initial.key, name, template, rules } });
      toast(isNew ? "Policy created" : "New version activated");
      onSaved();
    } catch (e) { setErr((e as Error).message); }
  }

  return (
    <Sheet open onClose={onClose} title={isNew ? "New policy" : `Edit ${initial.key}`}
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={save}>{isNew ? "Create & activate" : "Save as new version"}</button></>}>
      <div className="form">
        {isNew && (
          <Field label="Template" hint={t.description}>
            <select className="select" value={template} onChange={(e) => { setTemplate(e.target.value); setRules({ ...templates[e.target.value].defaults }); setName(templates[e.target.value].name); }}>
              {Object.entries(templates).map(([k, v]: any) => <option key={k} value={k}>{v.name}</option>)}
            </select>
          </Field>
        )}
        <Field label="Name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <div className="faint">Applies to: <span className="mono">{t.scope.join(", ")}</span></div>
        {Object.entries(t.defaults).map(([k, def]: any) => (
          <Field key={k} label={humanize(k)}>
            {k === "on_violation" ? (
              <select className="select" value={rules[k]} onChange={(e) => setRule(k, e.target.value)}>
                <option value="require_approval">Require approval</option>
                <option value="deny">Deny</option>
                {template === "budget_protection" && <option value="modify">Clamp to the allowed maximum</option>}
              </select>
            ) : k === "approval_role" ? (
              <select className="select" value={rules[k]} onChange={(e) => setRule(k, e.target.value)}>
                {["analyst", "operator", "admin", "owner"].map((r) => <option key={r} value={r}>{humanize(r)}</option>)}
              </select>
            ) : Array.isArray(def) ? (
              <input className="input" value={(rules[k] ?? []).join(", ")} placeholder="Comma-separated"
                onChange={(e) => setRule(k, e.target.value.split(",").map((s) => s.trim()).filter(Boolean))} />
            ) : typeof def === "number" ? (
              <input className="input" type="number" min={0} step="any" value={rules[k]} onChange={(e) => setRule(k, e.target.value === "" ? "" : Number(e.target.value))} />
            ) : (
              <input className="input" value={rules[k]} onChange={(e) => setRule(k, e.target.value)} />
            )}
          </Field>
        ))}
        <ErrorBox error={err} />
      </div>
    </Sheet>
  );
}

function Simulator() {
  const campaigns = useApi<any[]>("/campaigns");
  const agents = useApi<any[]>("/agents");
  const [f, setF] = useState({ action_type: ACTIONS[0], campaign: "", budget: "", agent: "" });
  const [result, setResult] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);
  const camp = campaigns.data?.find((c) => c.id === f.campaign);

  async function run() {
    setErr(null);
    try {
      const params: any = f.action_type === "ads.campaign.update_budget" ? { proposed_daily_budget: Number(f.budget), currency: camp?.currency }
        : f.action_type === "outreach.email.send" ? { recipients: Array.from({ length: Number(f.budget) || 1 }, (_, i) => `r${i}@example.com`) } : {};
      setResult(await api("/policies/evaluate", { body: {
        action: { action_type: f.action_type, target: { campaign_id: f.campaign }, parameters: params, idempotency_key: `dry-run-${Date.now()}` },
        agent_id: f.agent || null,
      } }));
    } catch (e) { setErr((e as Error).message); }
  }

  return (
    <Card title="Policy simulator" action={<Badge label="Dry run" tone="purple" />}>
      <div className="form">
        <Field label="Action"><select className="select" value={f.action_type} onChange={(e) => setF({ ...f, action_type: e.target.value })}>{ACTIONS.map((a) => <option key={a}>{a}</option>)}</select></Field>
        {f.action_type.startsWith("ads.") && (
          <Field label="Campaign"><select className="select" value={f.campaign} onChange={(e) => setF({ ...f, campaign: e.target.value })}>
            <option value="">Choose…</option>{campaigns.data?.map((c) => <option key={c.id} value={c.id}>{c.name} — {money(c.daily_budget, c.currency)}/day</option>)}
          </select></Field>
        )}
        {(f.action_type === "ads.campaign.update_budget" || f.action_type === "outreach.email.send") && (
          <Field label={f.action_type === "outreach.email.send" ? "Recipients" : "Proposed daily budget"}>
            <input className="input" type="number" min={0} value={f.budget} onChange={(e) => setF({ ...f, budget: e.target.value })} />
          </Field>
        )}
        <Field label="As agent" hint="Leave empty to evaluate as yourself.">
          <select className="select" value={f.agent} onChange={(e) => setF({ ...f, agent: e.target.value })}>
            <option value="">Me</option>{agents.data?.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
          </select>
        </Field>
        {can("analyst") && <button className="btn primary" onClick={run}>Run simulation</button>}
        <ErrorBox error={err} />
        {result && (
          <div className="stack">
            <div className="row"><span className="title">Result</span><Badge value={result.decision} /><span className="faint">Nothing was executed.</span></div>
            <ul className="list small">
              {result.reasons.map((r: any, i: number) => <li key={i}><Badge value={r.outcome} /> {r.message}</li>)}
            </ul>
          </div>
        )}
      </div>
    </Card>
  );
}
