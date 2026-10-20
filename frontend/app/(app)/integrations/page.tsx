"use client";

import { useState } from "react";
import { Badge, Card, Confirm, Dot, Empty, ErrorBox, Field, Icons, Loading, PageHead, Secret, Segmented, Sheet, toast } from "@/components/ui";
import { ago, api, can, humanize, useApi } from "@/lib/api";

const PROVIDERS: [string, string][] = [["n8n", "n8n"], ["google_ads", "Google Ads"], ["outreach", "PR outreach"]];

export default function Integrations() {
  const { data, error, loading, reload } = useApi<any[]>("/integrations");
  const [adding, setAdding] = useState(false);
  const [created, setCreated] = useState<any>(null);
  const [revoke, setRevoke] = useState<any>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function check(i: any) {
    setBusy(i.id);
    try {
      const r = await api(`/integrations/${i.id}/check`, { body: {} });
      toast(r.ok ? "Connection healthy" : `Check failed: ${r.detail.detail}`);
      reload();
    } catch (e) { toast((e as Error).message); } finally { setBusy(null); }
  }

  async function instrumentation(i: any) {
    const wf = await api(`/integrations/${i.id}/instrumentation`);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(wf, null, 2)], { type: "application/json" }));
    a.download = "campaignshield-error-reporter.json";
    a.click();
  }

  async function connectGoogle(i: any) {
    const r = await api(`/integrations/google-ads/oauth/start?integration_id=${i.id}`);
    window.location.href = r.url;
  }

  async function rotate(i: any) {
    const r = await api(`/integrations/${i.id}/rotate-key`, { body: {} });
    setCreated({ ...i, ingest_key: r.ingest_key, signing_secret: null, rotated: true });
  }

  async function fault(i: any, kind: string | null) {
    await api(`/integrations/${i.id}/simulate`, { body: kind ? { [kind]: true } : {} });
    toast(kind ? `Simulating ${humanize(kind).toLowerCase()} — run a check` : "Fault cleared");
    reload();
  }

  return (
    <>
      <PageHead title="Integrations" sub="Connected platforms, what CampaignShield can see, and what it can actually enforce.">
        {can("admin") && <button className="btn primary" onClick={() => setAdding(true)}>Add integration</button>}
      </PageHead>
      <ErrorBox error={error} onRetry={reload} />
      {loading && !data && <Loading />}
      {data && data.length === 0 && <Card><Empty title="No integrations yet" icon={Icons.integrations}>Add n8n or Google Ads to start monitoring.</Empty></Card>}
      <div className="grid grid-2">
        {data?.map((i) => (
          <Card key={i.id}>
            <div className="spread" style={{ alignItems: "flex-start" }}>
              <div>
                <div className="row" style={{ gap: 8 }}><h2 style={{ margin: 0, fontSize: 17 }}>{i.name}</h2></div>
                <div className="faint">{PROVIDERS.find(([p]) => p === i.provider)?.[1]} · added {ago(i.created_at)}</div>
              </div>
              <div className="row" style={{ gap: 6 }}><Badge value={i.mode} /><Badge value={i.status} /></div>
            </div>
            <div className={`banner ${i.capabilities.enforcement === "observe_only" ? "warn" : "info"} mt`} style={{ marginBottom: 0 }}>
              <span>{i.capabilities.enforcement === "observe_only"
                ? "Observe only: incidents are detected, but CampaignShield cannot block changes on this platform."
                : "Enforcement only applies to actions routed through the CampaignShield gateway."}</span>
            </div>
            <dl className="kv mt">
              <dt>Monitoring</dt><dd>{i.capabilities.monitoring.map(humanize).join(", ")}</dd>
              <dt>Gateway actions</dt><dd className="mono small">{i.capabilities.actions.length ? i.capabilities.actions.join(", ") : "None"}</dd>
              {i.provider === "n8n" && <><dt>Workflows</dt><dd>{i.workflows}</dd></>}
              {i.provider === "google_ads" && <><dt>Campaigns</dt><dd>{i.campaigns}</dd></>}
              <dt>Last check</dt><dd>{ago(i.health?.last_check_at)}</dd>
              {i.ingest_key_prefix && <><dt>Ingest key</dt><dd className="mono">{i.ingest_key_prefix}…</dd></>}
            </dl>
            {i.health?.last_error && <div className="error-box mt">{i.health.last_error}</div>}
            {i.capabilities.notes && <p className="faint">{i.capabilities.notes}</p>}
            {i.status !== "revoked" && (
              <div className="row mt">
                {can("operator") && <button className="btn sm" disabled={busy === i.id} onClick={() => check(i)}>{busy === i.id ? "Checking…" : "Check now"}</button>}
                {i.provider === "n8n" && <button className="btn sm" onClick={() => instrumentation(i)}>Instrumentation workflow</button>}
                {i.provider === "google_ads" && i.mode === "live" && can("admin") && <button className="btn sm primary" onClick={() => connectGoogle(i)}>{i.status === "connected" ? "Re-authorize" : "Connect Google account"}</button>}
                {can("admin") && <button className="btn sm" onClick={() => rotate(i)}>Rotate key</button>}
                {can("admin") && i.mode === "sandbox" && (
                  <select className="select inline" value="" onChange={(e) => fault(i, e.target.value || null)} aria-label="Simulate a fault">
                    <option value="">Simulate fault…</option>
                    <option value="outage">Provider outage</option>
                    <option value="auth_expired">Expired credential</option>
                    <option value="quota">Quota exhausted</option>
                    <option value="">Clear faults</option>
                  </select>
                )}
                {can("admin") && <button className="btn sm danger" onClick={() => setRevoke(i)}>Revoke</button>}
              </div>
            )}
          </Card>
        ))}
      </div>

      <AddIntegration open={adding} onClose={() => setAdding(false)} onCreated={(r) => { setAdding(false); setCreated(r); reload(); }} />

      <Sheet open={!!created} onClose={() => setCreated(null)} title={created?.rotated ? "New ingest key" : "Integration connected"}
        footer={<button className="btn primary" onClick={() => setCreated(null)}>Done</button>}>
        {created && (
          <div className="stack">
            <div className="banner warn" style={{ margin: 0 }}>Copy these now. Secrets are shown only once.</div>
            <Secret label="Ingest key (X-CampaignShield-Key)" value={created.ingest_key} />
            <Secret label="Webhook signing secret (optional HMAC)" value={created.signing_secret} />
            {created.ingest_url && (
              <div className="field">
                <span className="label">Send a test event</span>
                <pre className="code">{`curl -X POST ${created.ingest_url} \\
  -H "X-CampaignShield-Key: ${created.ingest_key}" \\
  -H "Content-Type: application/json" \\
  -d '{"event_id":"test-1","source":"${created.provider}","event_type":"workflow.execution.succeeded",
       "occurred_at":"${new Date().toISOString()}","resource":{"type":"workflow","id":"my-workflow"}}'`}</pre>
              </div>
            )}
            {created.provider === "google_ads" && created.mode === "live" && <p className="small muted">Next: choose “Connect Google account” to authorize read access via OAuth.</p>}
          </div>
        )}
      </Sheet>

      <Confirm open={!!revoke} onClose={() => setRevoke(null)} danger title={`Revoke ${revoke?.name}?`} confirmLabel="Revoke"
        body={<p className="muted">Stored credentials are deleted and the ingest key stops working immediately. History is kept.</p>}
        onConfirm={async () => { await api(`/integrations/${revoke.id}`, { method: "DELETE" }); toast("Integration revoked"); reload(); }} />
    </>
  );
}

function AddIntegration({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (r: any) => void }) {
  const [f, setF] = useState<any>({ provider: "n8n", mode: "sandbox", name: "", base_url: "", api_key: "", customer_id: "", allow_mutations: false, require_signature: false });
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });

  async function submit() {
    setBusy(true); setErr(null);
    try {
      const body: any = { provider: f.provider, mode: f.mode, name: f.name || PROVIDERS.find(([p]) => p === f.provider)![1], require_signature: f.require_signature };
      if (f.provider === "n8n" && f.mode === "live") Object.assign(body, { base_url: f.base_url, api_key: f.api_key });
      if (f.provider === "google_ads") Object.assign(body, { customer_id: f.customer_id || null, allow_mutations: f.allow_mutations });
      onCreated(await api("/integrations", { body }));
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  }

  return (
    <Sheet open={open} onClose={onClose} title="Add integration"
      footer={<><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy} onClick={submit}>{busy ? "Connecting…" : "Connect"}</button></>}>
      <div className="form">
        <Field label="Platform"><Segmented value={f.provider} onChange={(v) => setF({ ...f, provider: v, mode: v === "outreach" ? "sandbox" : f.mode })} options={PROVIDERS as [string, string][]} /></Field>
        {f.provider !== "outreach" && (
          <Field label="Mode" hint={f.mode === "sandbox" ? "Simulated provider state. Safe for demos and staging." : "Connects to the real platform."}>
            <Segmented value={f.mode} onChange={(v) => setF({ ...f, mode: v })} options={[["sandbox", "Sandbox"], ["live", "Live"]]} />
          </Field>
        )}
        <Field label="Name"><input className="input" value={f.name} onChange={set("name")} placeholder={PROVIDERS.find(([p]) => p === f.provider)![1]} /></Field>
        {f.provider === "n8n" && f.mode === "live" && (
          <>
            <Field label="n8n base URL" hint="Example: https://n8n.example.com"><input className="input" value={f.base_url} onChange={set("base_url")} /></Field>
            <Field label="n8n API key" hint="Settings → n8n API. Encrypted at rest."><input className="input" type="password" value={f.api_key} onChange={set("api_key")} autoComplete="off" /></Field>
          </>
        )}
        {f.provider === "google_ads" && (
          <>
            <Field label="Customer ID" hint="Format 123-456-7890"><input className="input" value={f.customer_id} onChange={set("customer_id")} /></Field>
            <label className="row small"><input type="checkbox" checked={f.allow_mutations} onChange={set("allow_mutations")} /> Allow gateway-controlled changes (pause, budget). Read-only by default.</label>
          </>
        )}
        <label className="row small"><input type="checkbox" checked={f.require_signature} onChange={set("require_signature")} /> Require HMAC-signed webhooks</label>
        <ErrorBox error={err} />
      </div>
    </Sheet>
  );
}
