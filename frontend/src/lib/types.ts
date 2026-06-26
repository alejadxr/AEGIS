// ─── Client / Auth ─────────────────────────────────────────────────
export interface Client {
  id: string;
  name: string;
  slug: string;
  api_key: string;
  settings: Record<string, unknown>;
  guardrails: GuardrailConfig;
  created_at: string;
  updated_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  client: Client;
}

// ─── Assets (Surface) ─────────────────────────────────────────────
export type AssetType = 'web' | 'server' | 'api' | 'dns' | 'cloud';
export type AssetStatus = 'active' | 'inactive' | 'decommissioned';

export interface Asset {
  id: string;
  client_id: string;
  hostname: string;
  ip_address: string;
  asset_type: AssetType;
  ports: number[];
  technologies: string[];
  status: AssetStatus;
  risk_score: number;
  last_scan_at: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

// ─── Vulnerabilities (Surface) ────────────────────────────────────
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type VulnStatus = 'open' | 'remediated' | 'accepted' | 'false_positive';

export interface Vulnerability {
  id: string;
  client_id: string;
  asset_id: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number | null;
  cve_id: string | null;
  template_id: string | null;
  evidence: string | null;
  status: VulnStatus;
  ai_risk_score: number | null;
  ai_analysis: string | null;
  remediation: string | null;
  found_at: string;
  remediated_at: string | null;
  asset?: Asset;
}

// ─── Scans (Surface) ─────────────────────────────────────────────
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface Scan {
  id: string;
  target: string;
  scan_type: string;
  status: ScanStatus;
  progress: number;
  results_count: number;
  started_at: string;
  completed_at: string | null;
}

// ─── Incidents (Response) ─────────────────────────────────────────
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved';

export interface Incident {
  id: string;
  client_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  source: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  source_ip: string | null;
  target_asset_id: string | null;
  ai_analysis: Record<string, unknown> | null;
  raw_alert: Record<string, unknown> | null;
  detected_at: string;
  contained_at: string | null;
  resolved_at: string | null;
  actions?: ResponseAction[];
}

// ─── Response Actions ─────────────────────────────────────────────
export type ActionStatus = 'pending' | 'approved' | 'executed' | 'failed' | 'rolled_back';
export type ActionType = 'block_ip' | 'isolate_host' | 'revoke_creds' | 'kill_process' | 'quarantine_file' | 'update_firewall' | 'notify_team' | 'custom';

export interface ResponseAction {
  id: string;
  incident_id: string;
  client_id: string;
  action_type: ActionType;
  target: string;
  parameters: Record<string, unknown>;
  status: ActionStatus;
  requires_approval: boolean;
  approved_by: string | null;
  ai_reasoning: string | null;
  result: Record<string, unknown> | null;
  executed_at: string | null;
  created_at: string;
}

// ─── Guardrails ───────────────────────────────────────────────────
export interface GuardrailConfig {
  auto_block_ip: boolean;
  auto_isolate_host: boolean;
  auto_revoke_creds: boolean;
  require_approval_above: Severity;
  max_auto_actions_per_hour: number;
  [key: string]: boolean | string | number;
}

// ─── Honeypots (Phantom) ──────────────────────────────────────────
export type HoneypotType = 'ssh' | 'http' | 'smb' | 'api' | 'database' | 'smtp';
export type HoneypotStatus = 'running' | 'stopped' | 'rotating';

export interface Honeypot {
  id: string;
  client_id: string;
  name: string;
  honeypot_type: HoneypotType;
  config: Record<string, unknown>;
  status: HoneypotStatus;
  ip_address: string | null;
  port: number | null;
  last_rotation: string | null;
  interactions_count: number;
  created_at: string;
}

export interface HoneypotInteraction {
  id: string;
  honeypot_id: string;
  client_id: string;
  source_ip: string;
  source_port: number | null;
  protocol: string;
  commands: string[];
  credentials_tried: Array<{ username: string; password: string }>;
  payloads: string[];
  session_duration: number | null;
  attacker_profile_id: string | null;
  raw_log: string | null;
  timestamp: string;
}

// ─── Attacker Profiles (Phantom) ──────────────────────────────────
export type Sophistication = 'script_kiddie' | 'intermediate' | 'advanced' | 'apt';

export interface AttackerProfile {
  id: string;
  client_id: string;
  source_ip: string;
  known_ips: string[];
  tools_used: string[];
  techniques: string[];
  sophistication: Sophistication;
  geo_data: {
    country: string;
    city: string;
    latitude: number;
    longitude: number;
  } | null;
  first_seen: string;
  last_seen: string;
  total_interactions: number;
  ai_assessment: string | null;
}

// ─── Threat Intelligence ──────────────────────────────────────────
export type IOCType = 'ip' | 'domain' | 'hash' | 'url' | 'email';

export interface ThreatIntel {
  id: string;
  ioc_type: IOCType;
  ioc_value: string;
  threat_type: string;
  confidence: number;
  source: string;
  tags: string[];
  first_seen: string;
  last_seen: string;
  expires_at: string | null;
}

// ─── Audit Log ────────────────────────────────────────────────────
export interface AuditLogEntry {
  id: string;
  client_id: string;
  incident_id: string | null;
  action: string;
  model_used: string;
  input_summary: string;
  ai_reasoning: string;
  decision: string;
  confidence: number;
  tokens_used: number;
  cost_usd: number;
  latency_ms: number;
  timestamp: string;
}

// ─── Dashboard ────────────────────────────────────────────────────
export interface DashboardOverview {
  total_assets: number;
  open_vulnerabilities: number;
  active_incidents: number;
  honeypot_interactions: number;
  assets_trend: number;
  vulns_trend: number;
  incidents_trend: number;
  interactions_trend: number;
}

export interface TimelineEvent {
  id: string;
  type: 'scan' | 'vulnerability' | 'incident' | 'action' | 'honeypot' | 'system';
  title: string;
  description: string;
  severity: Severity | null;
  module: 'surface' | 'response' | 'phantom' | 'system';
  timestamp: string;
}

export interface ThreatMapEntry {
  country: string;
  country_code: string;
  count: number;
  latitude: number;
  longitude: number;
}

// ─── Settings ─────────────────────────────────────────────────────
export interface ModelRouting {
  task_type: string;
  model: string;
  description: string;
}

export interface NotificationSettings {
  webhook_url: string;
  email_enabled: boolean;
  email_recipients: string[];
  notify_on_critical: boolean;
  notify_on_high: boolean;
  notify_on_actions: boolean;
}

// ─── API Response Wrappers ────────────────────────────────────────
export interface ApiResponse<T> {
  data: T;
  message?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}
