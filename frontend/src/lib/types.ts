export interface IncidentSummary {
  id: string; state: string; title: string; src_ip: string; hostname?: string | null; tier?: number | null;
  attack_type?: string | null; risk_score?: number | null; confidence?: number | null; level?: string | null;
  pending_level?: string | null; hold_reason?: string | null; escalation_reason?: string | null;
  detected_at: string; deadline_at?: string | null; contained_at?: string | null; closed_at?: string | null;
  mttc_ms?: number | null; false_positive?: boolean;
}

export interface Factor { name: string; weight: number; value: number; contribution: number; explanation: string }

export interface Incident extends IncidentSummary {
  asset_id?: number | null; entry_path?: string | null; approvals_required?: number; escalated_from?: string | null;
  observe_until?: string | null; decided_at?: string | null; network_stage?: number | null; cycle?: number;
  attack_source?: { ip?: string | null; country?: string | null; city?: string | null; asn?: string | null;
    provider?: string | null; reputation?: string; first_seen?: string | null; confidence?: number } | null;
  risk?: { risk_factors: Factor[]; confidence_factors: Factor[]; adjustments: Record<string, number>;
    blast_radius?: { threat_radius?: number; peers?: string[]; dependents?: string[]; containment_impact?: string } } | null;
  decision?: { level: string; auto_execute: boolean; reasons: string[]; approvals_required: number; circuit_breaker?: boolean;
    deadline_s: number } | null;
  memory?: { applied: boolean; pattern_id?: string; score?: number; best_score?: number; reason?: string } | null;
  mitre?: string[];
  entry?: { path: string; vector: string } | null;
}

export interface Transition { from_state: string | null; to_state: string; actor: string; at: string;
  detail: Record<string, unknown> }
export interface Action { id: string; action_type: string; layer: string; target: string; status: string;
  attempts: number; manual: boolean; provider: string; duration_ms: number; level: string; cycle: number }
export interface Check { check_name: string; passed: boolean; cycle: number; details: Record<string, unknown> }
export interface AuditRow { id: number; actor: string; action: string; target: string | null; reason: string | null;
  timestamp: string; incident_id: string | null; metadata: Record<string, unknown> }

export interface IncidentDetail {
  incident: Incident; asset: Asset | null; transitions: Transition[]; actions: Action[]; checks: Check[];
  approvals: { approver: string; level: string; created_at: string }[];
  evidence: { kind: string; sha256: string; collector: string; uri: string }[];
  chain_ok: boolean; chain_broken_at: number | null; event_count: number; audit: AuditRow[];
}

export interface Asset {
  id: number; hostname: string; ip: string; tier: number; role: string; segment: string; owner: string;
  isolatable: boolean; criticality: string; os: string; environment: string; in_change_window: boolean;
  dependents: string[]; status: string; network_stage: number | null; current_risk: number;
}

export interface Scenario { id: string; category: string; title_ar: string; title_en: string;
  default_failure: string; edge_case: number | null; target: string }

export interface Pattern { id: string; status: string; level: string; commands: string[]; hits: number;
  occurrences: number; fingerprint: Record<string, unknown>; created_at: string; approved_by: string | null }

export interface Kpis {
  incidents: number; auto_contained: number; auto_rate_pct: number; mttd_ms_avg: number | null;
  mttc_ms_avg: number | null; mttc_ms_p50: number | null; mttc_ms_p95: number | null;
  mttc_within_target_pct: number; false_positives: number; false_positive_rate_pct: number;
  escalations: number; sla_breaches: number; memory_hits: number; assets_contained: number;
  assets_total: number; business_continuity_pct: number;
}

export interface Report { window_start: string; window_end: string; kpis: Kpis; by_state: Record<string, number>;
  by_attack_type: Record<string, number>; by_level: Record<string, number>;
  recommendations: { en: string; ar: string }[] }

export interface StoredReport { id: number; window_start: string; window_end: string; generated_at: string;
  kpis: Kpis; body: Report }

export interface LiveMessage { type: string; incident_id: string | null; at: string; [k: string]: unknown }

export interface VerifyResult { passed: boolean; resumed?: boolean; hint?: string;
  probes: { probe: string; expected: string; observed: string; pass: boolean }[] }
export interface CommandResult { command: string; ok: boolean; message: string }
export interface Guards { circuit_breaker: { open_auto_containments: number; limit: number; window_min: number; tripped: boolean } }
