// Same-origin proxy to the API so the browser never needs CORS and API_URL is read at runtime.
const API = process.env.API_URL || "http://localhost:8000";
const FORWARD = ["authorization", "x-org-id", "content-type", "x-request-id"];

export const dynamic = "force-dynamic";

async function proxy(req: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  if (path.some((p) => p === "." || p === "..")) return Response.json({ error: { message: "Bad path" } }, { status: 400 });
  const target = `${API}/v1/${path.map(encodeURIComponent).join("/")}${new URL(req.url).search}`;
  const headers = new Headers();
  for (const h of FORWARD) {
    const v = req.headers.get(h);
    if (v) headers.set(h, v);
  }
  try {
    const res = await fetch(target, {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? undefined : await req.arrayBuffer(),
      redirect: "manual",
      cache: "no-store",
    });
    const out = new Headers();
    for (const h of ["content-type", "x-request-id"]) {
      const v = res.headers.get(h);
      if (v) out.set(h, v);
    }
    return new Response(res.body, { status: res.status, headers: out });
  } catch {
    return Response.json({ error: { code: "upstream_unavailable", message: "The CampaignShield API is unreachable. Try again shortly." } }, { status: 503 });
  }
}

export { proxy as GET, proxy as POST, proxy as PATCH, proxy as PUT, proxy as DELETE };
