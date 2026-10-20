"use client";

import Script from "next/script";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useRef, useState } from "react";
import { ErrorBox, Field, Icons } from "@/components/ui";
import { api, setSession } from "@/lib/api";

type Turnstile = {
  render: (el: HTMLElement, o: { sitekey: string; action: string; callback: (t: string) => void; "expired-callback": () => void }) => string;
  reset: (id: string) => void;
  remove: (id: string) => void;
};
declare global {
  interface Window { turnstile?: Turnstile }
}

export default function Login() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [form, setForm] = useState({ email: "", password: "", name: "", organization_name: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Cloudflare Turnstile: rendered only when the API reports a sitekey (TURNSTILE_SECRET set server-side).
  const [sitekey, setSitekey] = useState<string | null>(null);
  const [scriptReady, setScriptReady] = useState(false);
  const [token, setToken] = useState("");
  const box = useRef<HTMLDivElement>(null);
  const widget = useRef<string | null>(null);
  useEffect(() => { api("/auth/config").then((c) => setSitekey(c.turnstile_sitekey)).catch(() => {}); }, []);
  useEffect(() => {
    if (!sitekey || !scriptReady || !box.current || !window.turnstile) return;
    const ts = window.turnstile;
    setToken("");
    const id = ts.render(box.current, { sitekey, action: mode === "login" ? "login" : "signup", callback: setToken, "expired-callback": () => setToken("") });
    widget.current = id;
    return () => { ts.remove(id); widget.current = null; };
  }, [sitekey, scriptReady, mode]);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const creds = mode === "login" ? { email: form.email, password: form.password } : form;
      const body = sitekey ? { ...creds, turnstile_token: token } : creds;
      const r = await api(`/auth/${mode}`, { body });
      setSession({ token: r.token, email: r.user.email, orgId: r.organizations[0].id, orgs: r.organizations });
      router.replace("/");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
      // Tokens are single-use: get a fresh one before any retry.
      if (widget.current && window.turnstile) { window.turnstile.reset(widget.current); setToken(""); }
    }
  }

  return (
    <main className="login-wrap">
      {sitekey && <Script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" strategy="afterInteractive" onReady={() => setScriptReady(true)} />}
      <div className="login-card">
        <div className="brand"><span className="brand-mark">{Icons.shield}</span>CampaignShield</div>
        <p className="muted" style={{ textAlign: "center", margin: "0 0 28px" }}>
          {mode === "login" ? "Sign in to your control plane." : "Create your organization."}
        </p>
        <form className="card form" onSubmit={submit}>
          {mode === "register" && (
            <>
              <Field label="Your name"><input className="input" value={form.name} onChange={set("name")} autoComplete="name" /></Field>
              <Field label="Organization"><input className="input" required value={form.organization_name} onChange={set("organization_name")} placeholder="Acme Agency" /></Field>
            </>
          )}
          <Field label="Email"><input className="input" type="email" required value={form.email} onChange={set("email")} autoComplete="email" /></Field>
          <Field label="Password" hint={mode === "register" ? "At least 10 characters." : undefined}>
            <input className="input" type="password" required minLength={mode === "register" ? 10 : 1} value={form.password} onChange={set("password")}
              autoComplete={mode === "login" ? "current-password" : "new-password"} />
          </Field>
          {sitekey && <div ref={box} style={{ minHeight: 65 }} />}
          <ErrorBox error={error} />
          <button className="btn primary lg" disabled={busy || (!!sitekey && !token)}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}</button>
        </form>
        <p className="small muted" style={{ textAlign: "center", marginTop: 20 }}>
          {mode === "login" ? "New here? " : "Already have an account? "}
          <button className="btn ghost sm" onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(null); }}>
            {mode === "login" ? "Create an account" : "Sign in"}
          </button>
        </p>
      </div>
    </main>
  );
}
