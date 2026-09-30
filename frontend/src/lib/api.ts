/** Thin API client. The token lives in sessionStorage (cleared when the tab closes). */
const BASE = "/api/v1";
const TOKEN_KEY = "acrs.token";

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export function getToken(): string | null {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* storage unavailable: session-only login */ }
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  let body = init.body;
  if (init.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(init.json);
  }
  const res = await fetch(BASE + path, { ...init, headers, body });
  if (res.status === 401 && token) {
    setToken(null);
    window.dispatchEvent(new Event("acrs:logout"));
  }
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = await res.json(); msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* keep */ }
    throw new ApiError(res.status, msg);
  }
  return (await res.json()) as T;
}

export function wsUrl(path: string): string {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}${path}?token=${encodeURIComponent(getToken() ?? "")}`;
}
