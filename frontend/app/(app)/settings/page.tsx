"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Badge, Card, Confirm, ErrorBox, Field, Loading, PageHead, Secret, Segmented, Sheet, Switch, toast } from "@/components/ui";
import { api, can, getSession, humanize, setSession, useApi } from "@/lib/api";

export default function Settings() {
  const [tab, setTab] = useState("demo");
  return (
    <>
      <PageHead title="Settings">
        <Segmented value={tab} onChange={setTab} options={[["demo", "Demo"], ["org", "Organization"], ["members", "Members"], ["agents", "Agents"], ["account", "Account"]]} />
      </PageHead>
      {tab === "demo" && <Demo />}
      {tab === "org" && <OrgSettings />}
      {tab === "members" && <Members />}
      {tab === "agents" && <Agents />}
      {tab === "account" && <Account />}
    </>
  );
}

function Demo() {
  const { data } = useApi<any>("/demo/scenarios");
  const [seeded, setSeeded] = useState<any>(null);
  const [last, setLast] = useState<{ name: string; result: any } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function go(name: string | null) {
    setBusy(name ?? "seed");
    try {
      if (!name) { setSeeded(await api("/demo/seed", { body: {} })); toast("Sandbox ready"); }
      else { setLast({ name, result: await api(`/demo/scenarios/${name}`, { body: {} }) }); toast("Scenario ran — check Incidents"); }
    } catch (e) { toast((e as Error).message); } finally { setBusy(null); }
  }

  if (data && !data.enabled) return <Card><p className="muted">Demo mode is disabled in this environment.</p></Card>;
  return (
    <div className="stack">
      <Card title="Sandbox" action={can("admin") && <button className="btn primary" disabled={!!busy} onClick={() => go(null)}>{busy === "seed" ? "Loading…" : "Load sandbox data"}</button>}>
        <p className="muted" style={{ margin: 0 }}>Creates sandbox n8n, Google Ads and PR outreach integrations with 14 days of history, two agents and starter policies.
          Sandbox integrations never touch real accounts.</p>
        {seeded && (
          <div className="stack mt">
            {seeded.n8n_ingest_key && <Secret label="n8n sandbox ingest key" value={seeded.n8n_ingest_key} />}
            {Object.entries(seeded.agent_keys ?? {}).map(([name, key]) => <Secret key={name} label={`${name} API key`} value={key as string} />)}
            {!seeded.n8n_ingest_key && <p className="faint">Sandbox already existed; keys were shown when it was first created.</p>}
          </div>
        )}
      </Card>
      <Card title="Scenarios">
        <ul className="list">
          {data && Object.entries(data.scenarios).map(([name, desc]) => (
            <li key={name} className="spread">
              <div><div className="title">{humanize(name)}</div><div className="faint">{desc as string}</div></div>
              {can("admin") && <button className="btn sm" disabled={!!busy} onClick={() => go(name)}>{busy === name ? "Running…" : "Run"}</button>}
            </li>
          ))}
        </ul>
        {last && (
          <div className="mt">
            <div className="spread"><span className="title small">Result: {humanize(last.name)}</span><Link href="/incidents" className="small">Open incidents →</Link></div>
            <pre className="code mt">{JSON.stringify(last.result, null, 2)}</pre>
          </div>
        )}
      </Card>
    </div>
  );
}

function OrgSettings() {
  const s = getSession();
  const { data, reload } = useApi<any>(s ? `/organizations/${s.orgId}` : null);
  const [f, setF] = useState<any>(null);
  const [kill, setKill] = useState<boolean | null>(null);
  useEffect(() => { if (data) setF({ name: data.name, retention_days: data.settings.retention_days ?? 90, notify_webhook_url: data.settings.notify_webhook_url ?? "" }); }, [data]);
  if (!data || !f) return <Loading />;
  const admin = can("admin");

  async function save(body: any) {
    try { await api(`/organizations/${data.id}`, { method: "PATCH", body }); toast("Saved"); reload(); } catch (e) { toast((e as Error).message); }
  }

  return (
    <div className="grid grid-2">
      <Card title="Organization">
        <div className="form">
          <Field label="Name"><input className="input" disabled={!admin} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Event retention (days)"><input className="input" type="number" min={7} max={730} disabled={!admin} value={f.retention_days} onChange={(e) => setF({ ...f, retention_days: Number(e.target.value) })} /></Field>
          <Field label="Alert webhook (Slack-compatible)" hint="Receives a JSON {text} message for every new incident and approval request.">
            <input className="input" disabled={!admin} value={f.notify_webhook_url} placeholder="https://hooks.slack.com/…" onChange={(e) => setF({ ...f, notify_webhook_url: e.target.value })} />
          </Field>
          {admin && <button className="btn primary" style={{ alignSelf: "flex-start" }} onClick={() => save({ ...f, notify_webhook_url: f.notify_webhook_url || null })}>Save</button>}
        </div>
      </Card>
      <Card title="Emergency stop">
        <div className="spread">
          <div>
            <div className="title">Kill switch</div>
            <div className="faint">Denies every action routed through the gateway, for every agent, until turned off.</div>
          </div>
          <Switch danger label="Kill switch" on={!!data.settings.kill_switch} disabled={!admin} onChange={(v) => setKill(v)} />
        </div>
        {data.settings.kill_switch && <div className="banner danger mt" style={{ marginBottom: 0 }}>Engaged. Agents cannot change anything through CampaignShield.</div>}
      </Card>
      <Confirm open={kill !== null} onClose={() => setKill(null)} danger={!!kill} confirmLabel={kill ? "Engage kill switch" : "Disengage"}
        title={kill ? "Engage the kill switch?" : "Disengage the kill switch?"}
        body={<p className="muted" style={{ margin: 0 }}>{kill ? "All gateway actions will be denied immediately. Actions taken directly on provider platforms are not affected." : "Agents will be able to act again within their policies."}</p>}
        onConfirm={() => save({ kill_switch: kill })} />
    </div>
  );
}

function Members() {
  const { data, error, reload } = useApi<any[]>("/members");
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState({ email: "", role: "operator", temporary_password: "" });
  const [err, setErr] = useState<string | null>(null);
  const me = getSession()?.email;

  async function change(m: any, role: string) {
    try { await api(`/members/${m.id}`, { method: "PATCH", body: { role } }); toast("Role updated"); reload(); } catch (e) { toast((e as Error).message); }
  }

  return (
    <Card flush title="Members" action={can("admin") && <button className="btn sm primary" onClick={() => setAdding(true)}>Add member</button>}>
      <ErrorBox error={error} />
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Email</th><th>Role</th><th></th></tr></thead>
          <tbody>
            {data?.map((m) => (
              <tr key={m.id}>
                <td>{m.email}{m.email === me && <span className="faint"> (you)</span>}</td>
                <td>
                  {can("admin") && m.email !== me ? (
                    <select className="select inline" value={m.role} onChange={(e) => change(m, e.target.value)} aria-label="Role">
                      {["viewer", "analyst", "operator", "admin", "owner"].map((r) => <option key={r} value={r}>{humanize(r)}</option>)}
                    </select>
                  ) : <Badge label={humanize(m.role)} />}
                </td>
                <td style={{ textAlign: "right" }}>
                  {can("admin") && m.email !== me && <button className="btn sm danger" onClick={async () => { try { await api(`/members/${m.id}`, { method: "DELETE" }); reload(); } catch (e) { toast((e as Error).message); } }}>Remove</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Sheet open={adding} onClose={() => setAdding(false)} title="Add member"
        footer={<><button className="btn" onClick={() => setAdding(false)}>Cancel</button>
          <button className="btn primary" onClick={async () => {
            setErr(null);
            try { await api("/members", { body: { ...f, temporary_password: f.temporary_password || null } }); setAdding(false); toast("Member added"); reload(); }
            catch (e) { setErr((e as Error).message); }
          }}>Add</button></>}>
        <div className="form">
          <Field label="Email"><input className="input" type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
          <Field label="Role"><select className="select" value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
            {["viewer", "analyst", "operator", "admin"].map((r) => <option key={r} value={r}>{humanize(r)}</option>)}
          </select></Field>
          <Field label="Temporary password" hint="Only needed if this person doesn't have an account yet."><input className="input" type="password" value={f.temporary_password} onChange={(e) => setF({ ...f, temporary_password: e.target.value })} autoComplete="new-password" /></Field>
          <ErrorBox error={err} />
        </div>
      </Sheet>
    </Card>
  );
}

function Agents() {
  const { data, reload } = useApi<any[]>("/agents");
  const [creating, setCreating] = useState(false);
  const [f, setF] = useState({ name: "", allowed: "ads.campaign.*" });
  const [key, setKey] = useState<string | null>(null);

  async function update(a: any, body: any) {
    try { await api(`/agents/${a.id}`, { method: "PATCH", body }); toast("Agent updated"); reload(); } catch (e) { toast((e as Error).message); }
  }

  return (
    <Card flush title="Agents" action={can("admin") && <button className="btn sm primary" onClick={() => setCreating(true)}>New agent</button>}>
      <p className="faint" style={{ padding: "0 20px" }}>Agents call <span className="mono">POST /v1/actions/execute</span> with their key. They never receive provider credentials.</p>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Agent</th><th>Allowed actions</th><th>Requests</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {data?.map((a) => (
              <tr key={a.id}>
                <td><div className="title">{a.name}</div><div className="faint mono">{a.key_prefix}…</div></td>
                <td className="mono small">{a.allowed_actions.join(", ") || "none"}</td>
                <td>{a.actions_total}</td>
                <td><Badge value={a.status} /></td>
                <td style={{ textAlign: "right" }}>
                  {can("admin") && (
                    <div className="row" style={{ justifyContent: "flex-end" }}>
                      <button className="btn sm" onClick={async () => { const r = await api(`/agents/${a.id}/rotate-key`, { body: {} }); setKey(r.api_key); }}>Rotate key</button>
                      <button className={`btn sm ${a.status === "active" ? "danger" : ""}`} onClick={() => update(a, { status: a.status === "active" ? "suspended" : "active" })}>
                        {a.status === "active" ? "Suspend" : "Resume"}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Sheet open={creating} onClose={() => setCreating(false)} title="New agent"
        footer={<><button className="btn" onClick={() => setCreating(false)}>Cancel</button>
          <button className="btn primary" onClick={async () => {
            try {
              const r = await api("/agents", { body: { name: f.name, allowed_actions: f.allowed.split(",").map((s) => s.trim()).filter(Boolean) } });
              setCreating(false); setKey(r.api_key); reload();
            } catch (e) { toast((e as Error).message); }
          }}>Create</button></>}>
        <div className="form">
          <Field label="Name"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Allowed actions" hint="Comma-separated; wildcards allowed (ads.*). Anything else is denied."><input className="input mono" value={f.allowed} onChange={(e) => setF({ ...f, allowed: e.target.value })} /></Field>
        </div>
      </Sheet>
      <Sheet open={!!key} onClose={() => setKey(null)} title="Agent API key" footer={<button className="btn primary" onClick={() => setKey(null)}>Done</button>}>
        <div className="stack">
          <div className="banner warn" style={{ margin: 0 }}>Copy this key now. It won't be shown again.</div>
          <Secret label="API key" value={key} />
        </div>
      </Sheet>
    </Card>
  );
}

function Account() {
  const [name, setName] = useState("");
  return (
    <div className="grid grid-2">
      <Card title="New organization">
        <p className="muted small">Agencies can isolate each client in its own organization. Data and policies never cross organizations.</p>
        <div className="row">
          <input className="input" style={{ flex: 1 }} value={name} placeholder="Client name" onChange={(e) => setName(e.target.value)} aria-label="Organization name" />
          <button className="btn primary" disabled={!name} onClick={async () => {
            const org = await api("/organizations", { body: { name } });
            const s = getSession()!;
            setSession({ ...s, orgId: org.id, orgs: [...s.orgs, { id: org.id, name: org.name, role: "owner" }] });
            window.location.href = "/";
          }}>Create</button>
        </div>
      </Card>
      <Card title="Sessions">
        <p className="muted small">Sign out of every device, including this one.</p>
        <button className="btn danger" onClick={async () => { await api("/auth/sessions/revoke-all", { body: {} }); setSession(null); window.location.href = "/login"; }}>Sign out everywhere</button>
      </Card>
    </div>
  );
}
