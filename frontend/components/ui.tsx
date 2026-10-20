"use client";

import { ReactElement, ReactNode, cloneElement, isValidElement, useEffect, useId, useRef, useState } from "react";

const P = { fill: "none", stroke: "currentColor", strokeWidth: 1.7, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

export const Icons = {
  overview: <svg viewBox="0 0 24 24" {...P}><rect x="3.5" y="3.5" width="7" height="7" rx="2" /><rect x="13.5" y="3.5" width="7" height="7" rx="2" /><rect x="3.5" y="13.5" width="7" height="7" rx="2" /><rect x="13.5" y="13.5" width="7" height="7" rx="2" /></svg>,
  integrations: <svg viewBox="0 0 24 24" {...P}><path d="M9 7V3M15 7V3M7 7h10v4a5 5 0 0 1-10 0V7zM12 16v5" /></svg>,
  workflows: <svg viewBox="0 0 24 24" {...P}><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="18" r="2.5" /><circle cx="18" cy="6" r="2.5" /><path d="M8.5 6h7M18 8.5v7M8 7.8l8.2 8.4" /></svg>,
  campaigns: <svg viewBox="0 0 24 24" {...P}><path d="M4 19V5M4 19h16M8 15l4-4 3 3 5-6" /></svg>,
  incidents: <svg viewBox="0 0 24 24" {...P}><path d="M12 3.5 2.8 19.5h18.4L12 3.5z" /><path d="M12 10v4M12 17h.01" /></svg>,
  policies: <svg viewBox="0 0 24 24" {...P}><path d="M12 3 4.5 6v5.5c0 4.4 3.1 8.2 7.5 9.5 4.4-1.3 7.5-5.1 7.5-9.5V6L12 3z" /><path d="m9 12 2 2 4-4" /></svg>,
  approvals: <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="8.5" /><path d="m8.5 12 2.5 2.5 4.5-5" /></svg>,
  audit: <svg viewBox="0 0 24 24" {...P}><path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01" /></svg>,
  settings: <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="3" /><path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7" /></svg>,
  shield: <svg viewBox="0 0 24 24" {...P}><path d="M12 3 4.5 6v5.5c0 4.4 3.1 8.2 7.5 9.5 4.4-1.3 7.5-5.1 7.5-9.5V6L12 3z" /></svg>,
  check: <svg viewBox="0 0 24 24" {...P}><circle cx="12" cy="12" r="8.5" /><path d="m8.5 12 2.5 2.5 4.5-5" /></svg>,
  bell: <svg viewBox="0 0 24 24" {...P}><path d="M6 16V11a6 6 0 1 1 12 0v5l1.5 2h-15L6 16zM10 20.5a2 2 0 0 0 4 0" /></svg>,
};

export function Card({ title, action, children, className = "", flush }: { title?: ReactNode; action?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={`card ${flush ? "flush" : ""} ${className}`}>
      {(title || action) && (
        <div className="card-head" style={flush ? { padding: "18px 20px 0" } : undefined}>
          {typeof title === "string" ? <h2>{title}</h2> : title}
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function PageHead({ title, sub, children }: { title: string; sub?: ReactNode; children?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1 className="page-title">{title}</h1>
        {sub && <p className="page-sub">{sub}</p>}
      </div>
      {children && <div className="row">{children}</div>}
    </header>
  );
}

const TONES: Record<string, string> = {
  critical: "red", high: "orange", medium: "yellow", low: "blue", info: "",
  open: "red", investigating: "orange", awaiting_approval: "purple", mitigating: "blue", resolved: "green", closed: "",
  healthy: "green", degraded: "yellow", failing: "red", stalled: "orange", inactive: "", unknown: "",
  connected: "green", disconnected: "red", auth_expired: "red", pending_authorization: "yellow", revoked: "",
  ALLOW: "green", DENY: "red", REQUIRE_APPROVAL: "purple", MODIFY: "blue",
  executed: "green", verified: "green", denied: "red", rejected: "red", failed: "red", pending_approval: "purple", pending: "purple",
  approved: "green", proposed: "blue", done: "green", skipped: "", executing: "blue",
  enabled: "green", paused: "", active: "green", suspended: "red", sandbox: "purple", live: "blue",
  fresh: "green", delayed: "yellow", stale: "red", reversible: "green", irreversible: "red",
};

export function Badge({ value, label, tone }: { value?: string | null; label?: ReactNode; tone?: string }) {
  if (!value && !label) return null;
  const t = tone ?? TONES[value ?? ""] ?? "";
  return <span className={`badge ${t}`}>{label ?? (value ?? "").replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase())}</span>;
}

export function Dot({ tone }: { tone?: string }) {
  return <span className={`dot ${tone ?? ""}`} />;
}

export function Empty({ title, children, icon = Icons.check }: { title: string; children?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty">
      <div className="icon">{icon}</div>
      <h3>{title}</h3>
      {children && <div className="small">{children}</div>}
    </div>
  );
}

export function Loading({ rows = 3 }: { rows?: number }) {
  return (
    <div className="stack" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => <div key={i} className="skeleton" style={{ height: 52 }} />)}
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: string | null; onRetry?: () => void }) {
  if (!error) return null;
  return (
    <div className="error-box spread" role="alert">
      <span>{error}</span>
      {onRetry && <button className="btn sm" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: [T, string][]; onChange: (v: T) => void }) {
  return (
    <div className="seg" role="tablist">
      {options.map(([v, l]) => (
        <button key={v} role="tab" aria-selected={v === value} className={v === value ? "on" : ""} onClick={() => onChange(v)}>{l}</button>
      ))}
    </div>
  );
}

export function Switch({ on, onChange, danger, label, disabled }: { on: boolean; onChange: (v: boolean) => void; danger?: boolean; label: string; disabled?: boolean }) {
  return <button type="button" role="switch" aria-checked={on} aria-label={label} disabled={disabled} className={`switch ${on ? "on" : ""} ${danger ? "danger" : ""}`} onClick={() => onChange(!on)} />;
}

export function Sheet({ open, onClose, title, children, footer, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} className={`sheet ${wide ? "wide" : ""}`} onClose={onClose} onClick={(e) => e.target === ref.current && onClose()}>
      {open && (
        <>
          <div className="sheet-head">
            <h2>{title}</h2>
            <button className="btn ghost sm" onClick={onClose} aria-label="Close">Close</button>
          </div>
          <div className="sheet-body">{children}</div>
          {footer && <div className="sheet-foot">{footer}</div>}
        </>
      )}
    </dialog>
  );
}

/** Confirmation sheet for anything that changes external state. */
export function Confirm({ open, title, body, confirmLabel = "Confirm", danger, onConfirm, onClose }: {
  open: boolean; title: string; body: ReactNode; confirmLabel?: string; danger?: boolean; onConfirm: () => Promise<void> | void; onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <Sheet open={open} onClose={onClose} title={title}
      footer={<>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className={`btn ${danger ? "danger solid" : "primary"}`} disabled={busy} onClick={async () => {
          setBusy(true); setErr(null);
          try { await onConfirm(); onClose(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
        }}>{busy ? "Working…" : confirmLabel}</button>
      </>}>
      <div className="stack">{body}<ErrorBox error={err} /></div>
    </Sheet>
  );
}

let toastTimer: ReturnType<typeof setTimeout> | undefined;
export function toast(msg: string) {
  window.dispatchEvent(new CustomEvent("cs-toast", { detail: msg }));
}

export function Toaster() {
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    const h = (e: Event) => {
      setMsg((e as CustomEvent).detail);
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => setMsg(null), 3200);
    };
    window.addEventListener("cs-toast", h);
    return () => window.removeEventListener("cs-toast", h);
  }, []);
  return msg ? <div className="toast" role="status">{msg}</div> : null;
}

export function Sparkline({ values, height = 44, color = "var(--accent)", highlightLast }: { values: number[]; height?: number; color?: string; highlightLast?: boolean }) {
  if (values.length < 2) return <div className="faint" style={{ height }}>No data yet</div>;
  const w = 300, max = Math.max(...values) || 1;
  const pts = values.map((v, i) => [(i / (values.length - 1)) * w, height - 3 - (v / max) * (height - 6)]);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const [lx, ly] = pts[pts.length - 1];
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" style={{ width: "100%", height, display: "block" }} aria-hidden>
      <path d={`${line} L${w},${height} L0,${height} Z`} fill={color} opacity={0.1} />
      <path d={line} fill="none" stroke={color} strokeWidth={1.8} vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
      {highlightLast && <circle cx={lx} cy={ly} r={3.5} fill={color} />}
    </svg>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  const id = useId();
  // Link the label to a native input/select/textarea; composite controls (Segmented) keep a plain label.
  const native = isValidElement(children) && ["input", "select", "textarea"].includes(children.type as string);
  return (
    <div className="field">
      <label htmlFor={native ? id : undefined}>{label}</label>
      {native ? cloneElement(children as ReactElement<{ id?: string }>, { id }) : children}
      {hint && <span className="faint">{hint}</span>}
    </div>
  );
}

export function Secret({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <div className="field">
      <span className="label">{label}</span>
      <div className="secret">{value}</div>
      <button className="btn sm" style={{ alignSelf: "flex-start" }} onClick={() => { navigator.clipboard?.writeText(value); toast("Copied"); }}>Copy</button>
    </div>
  );
}
