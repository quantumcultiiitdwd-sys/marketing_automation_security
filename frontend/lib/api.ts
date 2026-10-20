"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type Org = { id: string; name: string; role: Role };
export type Role = "viewer" | "analyst" | "operator" | "admin" | "owner";
export type Session = { token: string; email: string; orgId: string; orgs: Org[] };

const KEY = "cs.session";
const ROLES: Role[] = ["viewer", "analyst", "operator", "admin", "owner"];

export function getSession(): Session | null {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "null");
  } catch {
    return null;
  }
}

export function setSession(s: Session | null) {
  try {
    if (s) localStorage.setItem(KEY, JSON.stringify(s));
    else localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: session lasts for this page only */
  }
}

export function currentRole(): Role {
  const s = getSession();
  return s?.orgs.find((o) => o.id === s.orgId)?.role ?? "viewer";
}

export function can(min: Role) {
  return ROLES.indexOf(currentRole()) >= ROLES.indexOf(min);
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown; text?: boolean } = {}): Promise<T> {
  const s = getSession();
  const res = await fetch(`/api${path}`, {
    method: opts.method ?? (opts.body !== undefined ? "POST" : "GET"),
    headers: {
      "Content-Type": "application/json",
      ...(s ? { Authorization: `Bearer ${s.token}`, "X-Org-Id": s.orgId } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    cache: "no-store",
  });
  if (res.status === 401 && s) {
    setSession(null);
    window.location.href = "/login";
  }
  if (!res.ok) {
    let msg: unknown = res.statusText;
    try {
      const j = await res.json();
      msg = j.error?.details?.[0]?.msg ? `${j.error.message}: ${j.error.details[0].msg}` : j.error?.message ?? msg;
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return (opts.text ? res.text() : res.json()) as Promise<T>;
}

/** Fetch on mount (and optionally poll). `reload()` refetches without clearing data. */
export function useApi<T = any>(path: string | null, pollMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const live = useRef(true);

  const reload = useCallback(async () => {
    if (!path) return;
    try {
      const d = await api<T>(path);
      if (live.current) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (live.current) setError((e as Error).message);
    } finally {
      if (live.current) setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    live.current = true;
    setLoading(true);
    reload();
    const t = pollMs ? setInterval(reload, pollMs) : undefined;
    return () => {
      live.current = false;
      if (t) clearInterval(t);
    };
  }, [reload, pollMs]);

  return { data, error, loading, reload, setData };
}

export function ago(iso?: string | null) {
  if (!iso) return "—";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 0) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function when(iso?: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function money(n: number | null | undefined, currency = "USD") {
  if (n == null) return "—";
  return new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: n >= 100 ? 0 : 2 }).format(n);
}

export function humanize(s?: string | null) {
  return (s ?? "").replace(/[._]/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}
