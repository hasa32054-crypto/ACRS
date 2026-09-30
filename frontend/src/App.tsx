import { AppProvider, useApp } from "./app/context";
import { publishLive, useFetch, useLive, useLiveTick } from "./app/hooks";
import { useRoute } from "./app/router";
import { Shell } from "./components/Shell";
import { Assets } from "./pages/Assets";
import { Audit } from "./pages/Audit";
import { CommandCenter } from "./pages/CommandCenter";
import { Emergency, Incidents } from "./pages/Incidents";
import { IncidentDetail } from "./pages/IncidentDetail";
import { Lab } from "./pages/Lab";
import { Login } from "./pages/Login";
import { Memory } from "./pages/Memory";
import { Reports } from "./pages/Reports";
import type { IncidentSummary } from "./lib/types";

function Console() {
  const { page, param } = useRoute();
  const online = useLive(publishLive);
  const tick = useLiveTick((m) => m.type === "emergency" || m.type === "state", 800);
  const esc = useFetch<IncidentSummary[]>("/emergency-queue", [tick]);
  let body;
  switch (page) {
    case "incidents": body = param ? <IncidentDetail key={param} id={param} /> : <Incidents />; break;
    case "emergency": body = <Emergency />; break;
    case "assets": body = <Assets />; break;
    case "lab": body = <Lab />; break;
    case "memory": body = <Memory />; break;
    case "reports": body = <Reports />; break;
    case "audit": body = <Audit />; break;
    default: body = <CommandCenter />;
  }
  return <Shell page={page} online={online} emergency={esc.data?.length ?? 0}>{body}</Shell>;
}

function Gate() {
  const { user } = useApp();
  return user ? <Console /> : <Login />;
}

export default function App() {
  return <AppProvider><Gate /></AppProvider>;
}
