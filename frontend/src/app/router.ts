import { useEffect, useState } from "react";

/** Hash router: #/incidents/<id>. Works behind any static server without rewrites. */
export function parseHash(hash: string): { page: string; param: string | null } {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  return { page: parts[0] ?? "", param: parts[1] ?? null };
}

export function useRoute() {
  const [route, setRoute] = useState(() => parseHash(location.hash));
  useEffect(() => {
    const on = () => { setRoute(parseHash(location.hash)); window.scrollTo(0, 0); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export function go(path: string): void {
  location.hash = path.startsWith("#") ? path : `#/${path.replace(/^\//, "")}`;
}
