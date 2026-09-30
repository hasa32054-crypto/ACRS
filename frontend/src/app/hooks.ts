import { useCallback, useEffect, useRef, useState } from "react";
import { api, wsUrl } from "../lib/api";
import type { LiveMessage } from "../lib/types";

/** Fetch JSON, refetch on demand; `deps` changes trigger a reload. */
export function useFetch<T>(path: string | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(false);
  const alive = useRef(true);
  const reload = useCallback(async () => {
    if (!path) return;
    setLoading(true);
    try {
      const d = await api<T>(path);
      if (alive.current) { setData(d); setError(null); }
    } catch (e) {
      if (alive.current) setError(e as Error);
    } finally {
      if (alive.current) setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    alive.current = true;
    void reload();
    return () => { alive.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reload, ...deps]);
  return { data, error, loading, reload, setData };
}

/** WebSocket live stream with automatic reconnect. */
export function useLive(onMessage: (m: LiveMessage) => void, incidentId?: string | null): boolean {
  const [online, setOnline] = useState(false);
  const handler = useRef(onMessage);
  handler.current = onMessage;
  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let ping: ReturnType<typeof setInterval> | undefined;
    let closed = false;
    const connect = () => {
      ws = new WebSocket(wsUrl(incidentId ? `/ws/incidents/${incidentId}` : "/ws/incidents"));
      ws.onopen = () => { setOnline(true); ping = setInterval(() => ws?.readyState === 1 && ws.send("ping"), 20000); };
      ws.onmessage = (ev) => { try { handler.current(JSON.parse(ev.data)); } catch { /* ignore malformed */ } };
      ws.onclose = () => {
        setOnline(false);
        clearInterval(ping);
        if (!closed) timer = setTimeout(connect, 2500);
      };
    };
    connect();
    return () => { closed = true; clearTimeout(timer); clearInterval(ping); ws?.close(); };
  }, [incidentId]);
  return online;
}

/** Re-render every `ms` (for countdowns). */
export function useNow(ms = 250): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const i = setInterval(() => setNow(Date.now()), ms); return () => clearInterval(i); }, [ms]);
  return now;
}

/* ---- in-app live bus: the shell owns one WebSocket, pages subscribe ---- */
type Listener = (m: LiveMessage) => void;
const listeners = new Set<Listener>();

export function publishLive(m: LiveMessage): void {
  listeners.forEach((l) => l(m));
}

export function useLiveBus(fn: Listener): void {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    const l: Listener = (m) => ref.current(m);
    listeners.add(l);
    return () => { listeners.delete(l); };
  }, []);
}

/** Counter that bumps (debounced) whenever a matching live message arrives: use it as a reload dependency. */
export function useLiveTick(match: (m: LiveMessage) => boolean = () => true, debounceMs = 350): number {
  const [tick, setTick] = useState(0);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  useLiveBus((m) => {
    if (!match(m)) return;
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setTick((x) => x + 1), debounceMs);
  });
  useEffect(() => () => clearTimeout(timer.current), []);
  return tick;
}
