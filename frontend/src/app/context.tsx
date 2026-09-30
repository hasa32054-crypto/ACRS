import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, setToken, getToken } from "../lib/api";
import { translate, enumLabel, type Key, type Lang } from "../lib/i18n";
import { tr } from "../lib/tr";

type Theme = "dark" | "light";
export interface User { username: string; role: string }
interface Toast { id: number; text: string; tone: "ok" | "crit" | "info" }

interface Ctx {
  lang: Lang; setLang: (l: Lang) => void; t: (k: Key, vars?: Record<string, string | number>) => string;
  e: (v: string | null | undefined) => string; x: (v: string | null | undefined) => string;
  theme: Theme; toggleTheme: () => void;
  user: User | null; login: (u: string, p: string) => Promise<void>; logout: () => void;
  toasts: Toast[]; toast: (text: string, tone?: Toast["tone"]) => void;
}

const AppCtx = createContext<Ctx | null>(null);

function stored<T extends string>(key: string, fallback: T): T {
  try { return (localStorage.getItem(key) as T) || fallback; } catch { return fallback; }
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => stored<Lang>("acrs.lang", "ar"));
  const [theme, setTheme] = useState<Theme>(() => stored<Theme>("acrs.theme", "dark"));
  const [user, setUser] = useState<User | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    const html = document.documentElement;
    html.lang = lang;
    html.dir = lang === "ar" ? "rtl" : "ltr";
    html.dataset.theme = theme;
    try { localStorage.setItem("acrs.lang", lang); localStorage.setItem("acrs.theme", theme); } catch { /* ignore */ }
  }, [lang, theme]);

  useEffect(() => {
    if (getToken()) api<User>("/auth/me").then(setUser).catch(() => setUser(null));
    const onLogout = () => setUser(null);
    window.addEventListener("acrs:logout", onLogout);
    return () => window.removeEventListener("acrs:logout", onLogout);
  }, []);

  const toast = useCallback((text: string, tone: Toast["tone"] = "info") => {
    const id = Date.now() + Math.random();
    setToasts((ts) => [...ts.slice(-3), { id, text, tone }]);
    setTimeout(() => setToasts((ts) => ts.filter((x) => x.id !== id)), 4500);
  }, []);

  const value = useMemo<Ctx>(() => ({
    lang, setLang: setLangState,
    t: (k, vars) => translate(lang, k, vars), e: (v) => enumLabel(lang, v), x: (v) => tr(lang, v),
    theme, toggleTheme: () => setTheme((x) => (x === "dark" ? "light" : "dark")),
    user,
    login: async (username, password) => {
      const r = await api<{ access_token: string; role: string }>("/auth/login", { method: "POST", json: { username, password } });
      setToken(r.access_token);
      setUser({ username, role: r.role });
    },
    logout: () => { setToken(null); setUser(null); },
    toasts, toast,
  }), [lang, theme, user, toasts, toast]);

  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>;
}

export function useApp(): Ctx {
  const c = useContext(AppCtx);
  if (!c) throw new Error("useApp outside AppProvider");
  return c;
}
