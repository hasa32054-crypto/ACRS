"""v10: three NON-hospital networks for the cross-sector generalisation test (PREREGISTRATION_v10.md).

Fixed before any v10 result was computed. Same building blocks as every earlier network (network.py): machines,
services with 1-2 replicas + dependencies, links an attacker can move along. Entry points keep the existing naming
convention (`web*` = internet-facing, `pc_*` = staff workstation), so the existing attack-chain generator
(phase8_ood.chain_scenarios) works unchanged. All weights are DESIGN ASSUMPTIONS on the same 1-10 scale.

  factory48 - manufacturing plant with an OT (industrial control) zone: PLCs, HMIs and the safety system can never be
              isolated (cutting them stops or endangers the process); SCADA twins; historian bridges IT and OT.
  bank42    - retail bank: core banking twins on one critical database, payment and ATM switch twins, an HSM that can
              never be isolated, SWIFT gateway, online and mobile banking.
  univ45    - university: LMS twins, student information system, exams, research cluster with a critical data store,
              lab instruments that can never be isolated, many student lab PCs.
"""
from __future__ import annotations

from qacrs.network import Machine, Network, Service, check


def _M(n, role, iso=True, crit=False, d=1):
    return Machine(n, role, iso, crit, d)


def _infra():
    m = [_M("dc1", "domain controller 1", crit=True, d=4), _M("dc2", "domain controller 2", crit=True, d=4),
         _M("files", "file server", d=2), _M("backup", "backup server", d=2), _M("email", "email server", d=2),
         _M("vpn", "VPN gateway", d=2), _M("wifi", "wireless controller", d=2)]
    s = [Service("logins", 30, ["dc1", "dc2"]), Service("email", 15, ["email"])]
    links = [("vpn", "dc1"), ("vpn", "files"), ("email", "dc1"), ("files", "dc1"), ("files", "dc2"), ("wifi", "dc2")]
    return m, s, links


def factory48() -> Network:
    m, s, L = _infra()
    m += [_M("scada1", "SCADA server (twin 1)", d=3), _M("scada2", "SCADA server (twin 2)", d=3),
          _M("historian", "process historian", crit=True, d=3),
          _M("mes1", "manufacturing execution system (twin 1)", d=2), _M("mes2", "manufacturing execution system (twin 2)", d=2),
          _M("erp_app", "ERP application", d=2), _M("erp_db", "ERP database", crit=True, d=3),
          _M("web1", "supplier portal (twin 1)"), _M("web2", "supplier portal (twin 2)"),
          _M("sis", "safety instrumented system", iso=False, d=5)]
    m += [_M(f"plc{i}", f"PLC line {i}", iso=False, d=5) for i in range(1, 7)]
    m += [_M(f"hmi{i}", f"operator HMI {i}", iso=False, d=4) for i in range(1, 5)]
    pcs = [f"pc_office{i}" for i in range(1, 13)] + ["pc_eng1", "pc_eng2"] + \
          [f"pc_ops{i}" for i in range(1, 5)] + [f"pc_admin{i}" for i in range(1, 4)]
    m += [_M(p, "engineering workstation" if "eng" in p else "staff workstation",
             d=3 if "eng" in p else 2 if "admin" in p else 1) for p in pcs]
    s += [Service("production_control", 45, ["scada1", "scada2"]),
          Service("mes", 30, ["mes1", "mes2"], ["historian", "erp_db"]),
          Service("erp", 25, ["erp_app"], ["erp_db"]),
          Service("supplier_portal", 10, ["web1", "web2"], ["erp_db"])]
    L += [("scada1", f"plc{i}") for i in (1, 2, 3)] + [("scada2", f"plc{i}") for i in (4, 5, 6)]
    L += [(f"hmi{i}", "scada1" if i % 2 else "scada2") for i in range(1, 5)]
    L += [("scada1", "historian"), ("scada2", "historian"), ("mes1", "historian"), ("mes2", "historian"),
          ("mes1", "erp_db"), ("mes2", "erp_db"), ("erp_app", "erp_db"), ("historian", "erp_db"),
          ("web1", "erp_app"), ("web2", "erp_app"), ("backup", "historian"), ("backup", "erp_db"),
          ("vpn", "pc_eng1"), ("pc_eng1", "sis"), ("pc_eng2", "sis")]
    for p in pcs:
        if p.startswith("pc_office"):
            L += [(p, "files"), (p, "email"), (p, "erp_app")]
        if p.startswith("pc_eng"):
            L += [(p, "scada1"), (p, "scada2"), (p, "historian"), (p, "plc1" if p.endswith("1") else "plc4")]
        if p.startswith("pc_ops"):
            L += [(p, "mes1" if int(p[-1]) % 2 else "mes2"), (p, "files")]
        if p.startswith("pc_admin"):
            L += [(p, "dc1"), (p, "erp_db"), (p, "backup")]
    net = Network("factory48", m, s, L)
    check(net)
    return net


def bank42() -> Network:
    m, s, L = _infra()
    m += [_M("core_app1", "core banking app (twin 1)", d=2), _M("core_app2", "core banking app (twin 2)", d=2),
          _M("core_db", "core banking database", crit=True, d=3),
          _M("pay_gw1", "payments gateway (twin 1)", d=2), _M("pay_gw2", "payments gateway (twin 2)", d=2),
          _M("swift", "SWIFT messaging gateway", crit=True, d=3),
          _M("atm_sw1", "ATM switch (twin 1)", d=2), _M("atm_sw2", "ATM switch (twin 2)", d=2),
          _M("hsm", "hardware security module", iso=False, d=5),
          _M("web1", "online banking (twin 1)"), _M("web2", "online banking (twin 2)"),
          _M("api_gw", "mobile banking API", d=2), _M("fraud", "fraud scoring engine", d=2), _M("crm", "CRM", d=1)]
    pcs = [f"pc_teller{i}" for i in range(1, 11)] + [f"pc_branch{i}" for i in range(1, 7)] + \
          [f"pc_admin{i}" for i in range(1, 4)] + ["pc_dev1", "pc_dev2"]
    m += [_M(p, "staff workstation", d=2 if "admin" in p else 1) for p in pcs]
    s += [Service("core_banking", 45, ["core_app1", "core_app2"], ["core_db"]),
          Service("payments", 40, ["pay_gw1", "pay_gw2"], ["core_db"]),
          Service("atm", 35, ["atm_sw1", "atm_sw2"], ["core_db"]),
          Service("online_banking", 25, ["web1", "web2"], ["core_db"]),
          Service("mobile_banking", 25, ["api_gw"], ["core_db"]),
          Service("swift_messaging", 35, ["swift"]),
          Service("fraud_check", 20, ["fraud"], ["core_db"]),
          Service("crm", 10, ["crm"], ["core_db"])]
    L += [("core_app1", "core_db"), ("core_app2", "core_db"), ("pay_gw1", "core_db"), ("pay_gw2", "core_db"),
          ("pay_gw1", "hsm"), ("pay_gw2", "hsm"), ("atm_sw1", "core_db"), ("atm_sw2", "core_db"),
          ("atm_sw1", "hsm"), ("atm_sw2", "hsm"), ("swift", "pay_gw1"), ("web1", "core_app1"), ("web2", "core_app2"),
          ("api_gw", "core_app1"), ("fraud", "core_db"), ("crm", "core_db"), ("backup", "core_db")]
    for p in pcs:
        if p.startswith("pc_teller"):
            L += [(p, "core_app1" if int(p[-1]) % 2 else "core_app2"), (p, "files")]
        if p.startswith("pc_branch"):
            L += [(p, "crm"), (p, "email"), (p, "files")]
        if p.startswith("pc_admin"):
            L += [(p, "dc1"), (p, "core_db"), (p, "backup")]
        if p.startswith("pc_dev"):
            L += [(p, "api_gw"), (p, "files")]
    net = Network("bank42", m, s, L)
    check(net)
    return net


def univ45() -> Network:
    m, s, L = _infra()
    m += [_M("lms1", "learning management system (twin 1)", d=2), _M("lms2", "learning management system (twin 2)", d=2),
          _M("sis_app", "student information system", d=2), _M("sis_db", "student records database", crit=True, d=3),
          _M("web1", "public website (twin 1)"), _M("web2", "public website (twin 2)"),
          _M("exam", "online exam system", d=2), _M("lib", "library system"),
          _M("hpc", "research cluster head node", d=3), _M("hpc_store", "research data store", crit=True, d=3),
          _M("lab_inst1", "research instrument 1", iso=False, d=4), _M("lab_inst2", "research instrument 2", iso=False, d=4)]
    pcs = [f"pc_lab{i}" for i in range(1, 13)] + [f"pc_staff{i}" for i in range(1, 9)] + \
          [f"pc_admin{i}" for i in range(1, 4)] + [f"pc_res{i}" for i in range(1, 4)]
    m += [_M(p, "staff workstation" if not p.startswith("pc_lab") else "student lab PC",
             d=2 if "admin" in p else 1) for p in pcs]
    s += [Service("lms", 30, ["lms1", "lms2"], ["sis_db"]), Service("registration", 25, ["sis_app"], ["sis_db"]),
          Service("website", 10, ["web1", "web2"]), Service("exams", 35, ["exam"], ["sis_db"]),
          Service("research_compute", 20, ["hpc"], ["hpc_store"]), Service("library", 5, ["lib"])]
    L += [("lms1", "sis_db"), ("lms2", "sis_db"), ("sis_app", "sis_db"), ("exam", "sis_db"), ("web1", "lms1"),
          ("web2", "lms2"), ("hpc", "hpc_store"), ("lab_inst1", "hpc_store"), ("lab_inst2", "hpc_store"),
          ("backup", "sis_db"), ("backup", "hpc_store"), ("vpn", "hpc")]
    for p in pcs:
        if p.startswith("pc_lab"):
            L += [(p, "lms1" if int(p[-1]) % 2 else "lms2"), (p, "files"), (p, "lib")]
        if p.startswith("pc_staff"):
            L += [(p, "sis_app"), (p, "lms1"), (p, "email")]
        if p.startswith("pc_admin"):
            L += [(p, "dc1"), (p, "sis_db"), (p, "backup")]
        if p.startswith("pc_res"):
            L += [(p, "hpc"), (p, "files")]
    net = Network("univ45", m, s, L)
    check(net)
    return net


SECTORS = {"factory48": factory48, "bank42": bank42, "univ45": univ45}
CHAIN_SEEDS = {"factory48": 7401, "bank42": 7402, "univ45": 7403}
RAND_SEEDS = {"factory48": 9401, "bank42": 9402, "univ45": 9403}
N_CHAIN, N_RAND = 200, 200

if __name__ == "__main__":
    for name, f in SECTORS.items():
        n = f()
        print(f"{name}: {len(n.machines)} machines, {len(n.services)} services, {len(n.links)} links, "
              f"never-isolate {sum(not x.isolatable for x in n.machines)}, critical {sum(x.critical for x in n.machines)}")
