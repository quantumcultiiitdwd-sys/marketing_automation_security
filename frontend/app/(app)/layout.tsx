"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { Icons, Toaster } from "@/components/ui";
import { api, getSession, Session, setSession, useApi } from "@/lib/api";

const NAV = [
  ["/", "Overview", Icons.overview],
  ["/integrations", "Integrations", Icons.integrations],
  ["/workflows", "Workflows", Icons.workflows],
  ["/campaigns", "Campaigns", Icons.campaigns],
  ["/incidents", "Incidents", Icons.incidents],
  ["/policies", "Policies", Icons.policies],
  ["/approvals", "Approvals", Icons.approvals],
  ["/audit", "Audit", Icons.audit],
  ["/settings", "Settings", Icons.settings],
] as const;

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const path = usePathname();
  const [session, setS] = useState<Session | null>(null);

  useEffect(() => {
    const s = getSession();
    if (!s) router.replace("/login");
    else setS(s);
  }, [router]);

  const counts = useApi<any>(session ? "/dashboard/summary?days=1" : null, 20000);
  if (!session) return null;

  const badge = (href: string) => {
    const d = counts.data;
    if (!d) return 0;
    if (href === "/incidents") return d.incidents.open;
    if (href === "/approvals") return d.protection.pending_approvals;
    return 0;
  };

  function switchOrg(id: string) {
    const s = { ...session!, orgId: id };
    setSession(s);
    setS(s);
    window.location.href = "/";
  }

  async function logout() {
    try { await api("/auth/logout", { body: {} }); } catch { /* already expired */ }
    setSession(null);
    router.replace("/login");
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">{Icons.shield}</span>CampaignShield</div>
        <nav className="nav" aria-label="Main">
          {NAV.map(([href, label, icon]) => {
            const active = href === "/" ? path === "/" : path.startsWith(href);
            const n = badge(href);
            return (
              <Link key={href} href={href} className={active ? "active" : ""} aria-current={active ? "page" : undefined}>
                {icon}{label}{n > 0 && <span className="count">{n}</span>}
              </Link>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          {session.orgs.length > 1 ? (
            <select className="select inline" value={session.orgId} onChange={(e) => switchOrg(e.target.value)} aria-label="Organization">
              {session.orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          ) : (
            <span className="small" style={{ padding: "0 6px", fontWeight: 500 }}>{session.orgs[0]?.name}</span>
          )}
          <div className="spread" style={{ padding: "0 6px" }}>
            <span className="faint" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{session.email}</span>
            <button className="btn ghost sm" onClick={logout}>Sign out</button>
          </div>
        </div>
      </aside>
      <main className="main">{children}</main>
      <Toaster />
    </div>
  );
}
