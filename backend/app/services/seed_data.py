"""Demo CMDB: 20 assets across Tier-0/1/2. Fictional data only."""

ASSETS = [
    # hostname, ip, tier, role, segment, owner, criticality, os, extra
    ("DC-01", "10.10.0.5", 0, "domain-controller", "tier0", "Identity-Ops", "critical", "Windows Server 2022",
     {"pool_size": 2, "dependents": ["ALL-AD-CLIENTS"], "edr_device_id": "edr-dc01"}),
    ("DC-02", "10.10.0.6", 0, "domain-controller", "tier0", "Identity-Ops", "critical", "Windows Server 2022",
     {"pool_size": 2, "dependents": ["ALL-AD-CLIENTS"], "edr_device_id": "edr-dc02"}),
    ("K8S-CP-01", "10.50.0.10", 0, "k8s-control-plane", "k8s-cp", "Platform", "critical", "Ubuntu 22.04",
     {"pool_size": 3, "environment": "k8s", "dependents": ["ALL-WORKLOADS"], "edr_device_id": "edr-k8scp01"}),
    ("PKI-CA-01", "10.10.0.20", 0, "pki", "tier0", "Identity-Ops", "critical", "Windows Server 2022",
     {"dependents": ["ALL-CERTIFICATES"], "edr_device_id": "edr-pki01"}),
    ("HR-APP-01", "10.20.1.11", 1, "hr-app", "hr-apps", "HR-IT", "high", "Windows Server 2022",
     {"pool": "hr-pool", "pool_size": 2, "dependents": ["HR-DB-01", "HR-API-GW"], "edr_device_id": "edr-hr01"}),
    ("HR-APP-02", "10.20.1.12", 1, "hr-app", "hr-apps", "HR-IT", "high", "Windows Server 2022",
     {"pool": "hr-pool", "pool_size": 2, "dependents": ["HR-DB-01", "HR-API-GW"], "edr_device_id": "edr-hr02"}),
    ("HR-DB-01", "10.20.2.21", 1, "database", "hr-data", "HR-IT", "high", "RHEL 9 / PostgreSQL",
     {"edr_device_id": "edr-hrdb01"}),
    ("HR-API-GW", "10.20.3.40", 1, "api-gateway", "hr-apps", "HR-IT", "high", "Kong on Ubuntu",
     {"pool_size": 2, "dependents": ["HR-APP-01", "HR-APP-02"], "edr_device_id": "edr-hrgw"}),
    ("ERP-PROD-01", "10.30.1.10", 1, "erp-app", "erp", "Finance-IT", "high", "SUSE 15 / SAP S/4",
     {"dependents": ["ERP-DB-01"], "in_change_window": True, "edr_device_id": "edr-erp01"}),
    ("ERP-DB-01", "10.30.2.10", 1, "database", "erp", "Finance-IT", "high", "SUSE 15 / HANA",
     {"edr_device_id": "edr-erpdb01"}),
    ("FIN-API-01", "10.30.3.15", 1, "api-gateway", "erp", "Finance-IT", "high", "Ubuntu 22.04",
     {"pool_size": 2, "dependents": ["ERP-PROD-01"], "edr_device_id": "edr-finapi"}),
    ("API-GW-AWS-01", "172.31.10.5", 1, "web-frontend", "aws-prod-vpc", "Digital", "high", "Amazon Linux 2023",
     {"pool": "api-tg", "pool_size": 3, "environment": "aws", "cloud_instance_id": "i-0a1b2c3d4e5f60718",
      "dependents": ["MOBILE-APP", "PARTNER-API"], "edr_device_id": "edr-awsgw01"}),
    ("MRI-CTRL-02", "10.60.3.8", 1, "medical-device", "medical", "Clinical-Eng", "high", "Windows 7 Embedded",
     {"isolatable": False, "dependents": ["PACS-01"]}),
    ("VPN-GW-01", "10.0.0.2", 1, "vpn-gateway", "edge", "Network-Ops", "high", "Vendor appliance",
     {"pool_size": 2, "dependents": ["REMOTE-USERS"], "edr_device_id": None}),
    ("WS-FIN-023", "10.40.5.23", 2, "workstation", "user-finance", "Finance", "low", "Windows 11",
     {"edr_device_id": "edr-ws0523"}),
    ("WS-FIN-031", "10.40.5.31", 2, "workstation", "user-finance", "Finance", "low", "Windows 11",
     {"edr_device_id": "edr-ws0531"}),
    ("WS-FIN-044", "10.40.5.44", 2, "workstation", "user-finance", "Finance", "low", "Windows 11",
     {"edr_device_id": "edr-ws0544"}),
    ("WS-HR-011", "10.40.6.11", 2, "workstation", "user-hr", "HR", "low", "Windows 11",
     {"edr_device_id": "edr-ws0611"}),
    ("K8S-NODE-04", "10.50.1.14", 2, "k8s-node", "k8s-workers", "Platform", "medium", "Ubuntu 22.04",
     {"pool_size": 6, "environment": "k8s", "edr_device_id": "edr-k8sn04"}),
    ("DEV-BUILD-07", "10.70.0.7", 2, "build-server", "dev", "Engineering", "medium", "Ubuntu 22.04",
     {"edr_device_id": "edr-build07"}),
]


def asset_rows() -> list[dict]:
    rows = []
    for i, (hostname, ip, tier, role, segment, owner, crit, os_, extra) in enumerate(ASSETS, start=1):
        rows.append({"id": i, "hostname": hostname, "ip": ip, "tier": tier, "role": role, "segment": segment,
                     "owner": owner, "criticality": crit, "os": os_, "isolatable": extra.get("isolatable", True),
                     "pool": extra.get("pool"), "pool_size": extra.get("pool_size", 1),
                     "environment": extra.get("environment", "on-prem"),
                     "cloud_instance_id": extra.get("cloud_instance_id"),
                     "edr_device_id": extra.get("edr_device_id"),
                     "in_change_window": extra.get("in_change_window", False),
                     "dependents": extra.get("dependents", [])})
    return rows
