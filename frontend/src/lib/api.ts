const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

function getApiKey(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('aegis_api_key');
}

export function getJwtToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('aegis_jwt_token');
}

export function setApiKey(key: string): void {
  localStorage.setItem('aegis_api_key', key);
}

export function setJwtToken(token: string): void {
  localStorage.setItem('aegis_jwt_token', token);
}

export function clearApiKey(): void {
  localStorage.removeItem('aegis_api_key');
}

export function clearJwtToken(): void {
  localStorage.removeItem('aegis_jwt_token');
}

export function hasApiKey(): boolean {
  return !!getApiKey();
}

export function hasJwtToken(): boolean {
  return !!getJwtToken();
}

export function hasAuth(): boolean {
  return hasApiKey() || hasJwtToken();
}

// Track whether we are already redirecting to avoid loops
let _isRedirectingToLogin = false;

export function isRedirectingToLogin(): boolean {
  return _isRedirectingToLogin;
}

function handleSessionExpired(): void {
  if (_isRedirectingToLogin) return;
  _isRedirectingToLogin = true;
  localStorage.removeItem('aegis_api_key');
  localStorage.removeItem('aegis_jwt_token');
  if (typeof window !== 'undefined') {
    window.location.href = '/';
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit & { skipAuth?: boolean } = {}
): Promise<T> {
  const { skipAuth, ...fetchOptions } = options;
  const apiKey = getApiKey();
  const jwtToken = getJwtToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(fetchOptions.headers as Record<string, string>),
  };

  if (!skipAuth) {
    if (jwtToken) {
      headers['Authorization'] = `Bearer ${jwtToken}`;
    } else if (apiKey) {
      headers['X-API-Key'] = apiKey;
    }
  }

  const response = await fetch(`${BASE_URL}${endpoint}`, {
    ...fetchOptions,
    headers,
  });

  if (!response.ok) {
    // Global 401 interceptor: clear tokens and redirect to login
    // Skip for auth endpoints (login/register) to avoid redirect loops
    if (
      response.status === 401 &&
      !endpoint.startsWith('/auth/') &&
      !endpoint.startsWith('/onboarding/')
    ) {
      handleSessionExpired();
      throw new ApiError(401, 'Session expired');
    }
    const body = await response.text();
    throw new ApiError(response.status, body || `HTTP ${response.status}`);
  }

  if (response.status === 204) return undefined as T;
  return response.json();
}

// ---------------------------------------------------------------------------
// Tauri Desktop Agent IPC
// ---------------------------------------------------------------------------
// These functions are only available when running inside the Tauri desktop app.
// In the browser, window.__TAURI__ is undefined and calls return null.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare global {
  interface Window {
    __TAURI__?: {
      core: {
        invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
      };
      event: {
        listen: (event: string, handler: (event: { payload: string }) => void) => Promise<() => void>;
      };
    };
  }
}

function isTauri(): boolean {
  return typeof window !== 'undefined' && !!window.__TAURI__;
}

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T | null> {
  if (!isTauri()) return null;
  try {
    return await window.__TAURI__!.core.invoke(cmd, args) as T;
  } catch (err) {
    console.error(`Tauri invoke '${cmd}' failed:`, err);
    return null;
  }
}

export const tauriAgent = {
  /** Check if we're running inside the Tauri desktop app */
  isDesktop: isTauri,

  /** Request agent status (response comes via agent-event) */
  status: () => tauriInvoke<string>('agent_status'),

  /** Trigger network discovery (response comes via agent-event) */
  discover: () => tauriInvoke<string>('agent_discover'),

  /** Request recent events (response comes via agent-event) */
  getEvents: () => tauriInvoke<string>('agent_get_events'),

  /** Request system info (response comes via agent-event) */
  getSystemInfo: () => tauriInvoke<string>('agent_get_system_info'),

  /** Trigger forensic snapshot (response comes via agent-event) */
  forensicSnapshot: () => tauriInvoke<string>('agent_forensic_snapshot'),

  /** Stop the agent sidecar */
  stop: () => tauriInvoke<string>('agent_stop'),

  /** Check if the agent process is running */
  isRunning: () => tauriInvoke<boolean>('agent_is_running'),

  /** Listen for real-time events from the agent sidecar */
  onEvent: async (handler: (data: Record<string, unknown>) => void): Promise<(() => void) | null> => {
    if (!isTauri()) return null;
    const unlisten = await window.__TAURI__!.event.listen('agent-event', (event) => {
      try {
        const parsed = typeof event.payload === 'string'
          ? JSON.parse(event.payload)
          : event.payload;
        handler(parsed);
      } catch {
        // non-JSON payload, pass raw
        handler({ type: 'raw', data: event.payload });
      }
    });
    return unlisten;
  },
};

// ---------------------------------------------------------------------------
// AI mode helper — reads ai_mode from /api/v1/health
// ---------------------------------------------------------------------------

export type AiMode = 'required' | 'optional' | 'disabled';

export async function getAiMode(): Promise<AiMode> {
  try {
    const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
    const res = await fetch(`${BASE}/health`, { cache: 'no-store' });
    if (!res.ok) return 'optional';
    const data = await res.json();
    const mode = data?.ai_mode;
    if (mode === 'required' || mode === 'optional' || mode === 'disabled') return mode;
    return 'optional';
  } catch {
    return 'optional';
  }
}

export const api = {
  // Generic helpers (used by newer pages: antivirus, edr, ...)
  get: <T>(endpoint: string) => request<T>(endpoint),
  post: <T>(endpoint: string, body?: unknown) =>
    request<T>(endpoint, {
      method: 'POST',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  put: <T>(endpoint: string, body?: unknown) =>
    request<T>(endpoint, {
      method: 'PUT',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  patch: <T>(endpoint: string, body?: unknown) =>
    request<T>(endpoint, {
      method: 'PATCH',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  delete: <T>(endpoint: string) => request<T>(endpoint, { method: 'DELETE' }),

  // Onboarding
  onboarding: {
    signup: (orgName: string, name: string, email: string, password: string) =>
      request<{ api_key: string; token: string; client_id: string; client_name: string }>('/onboarding/signup', {
        method: 'POST',
        body: JSON.stringify({ org_name: orgName, admin_name: name, admin_email: email, admin_password: password }),
        skipAuth: true,
      }),
  },

  // Auth
  auth: {
    login: (apiKey: string) =>
      request<{ token: string; client_id: string; client_name: string }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ api_key: apiKey }),
        skipAuth: true,
      }),
    loginCredentials: (email: string, password: string) =>
      request<{ token: string; user: { id: string; email: string; name: string; role: string } }>('/auth/user/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
        skipAuth: true,
      }),
    register: (name: string, email: string, password: string) =>
      request<{ token: string; user: { id: string; email: string; name: string; role: string } }>('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ name, email, password }),
        skipAuth: true,
      }),
    me: () => request<{ name: string; slug: string }>('/auth/me'),
  },

  // Dashboard
  dashboard: {
    overview: () =>
      request<{
        total_assets: number;
        open_vulnerabilities: number;
        active_incidents: number;
        honeypot_interactions: number;
        assets_trend: number;
        vulns_trend: number;
        incidents_trend: number;
        interactions_trend: number;
      }>('/dashboard/overview'),
    timeline: () =>
      request<Array<{
        id: string;
        type: string;
        title: string;
        description: string;
        severity: string | null;
        module: string;
        timestamp: string;
      }>>('/dashboard/timeline'),
    threatMap: () =>
      request<Array<{
        country: string;
        country_code: string;
        count: number;
      }>>('/dashboard/threat-map'),
  },

  // Surface
  surface: {
    scan: (target: string, scanType: string) =>
      request('/surface/scan', {
        method: 'POST',
        body: JSON.stringify({ target, scan_type: scanType }),
      }),
    scans: () => request<Array<{
      id: string;
      target: string;
      scan_type: string;
      status: string;
      progress: number;
      results_count: number;
      started_at: string;
    }>>('/surface/scans'),
    assets: (params?: Record<string, string>) => {
      const query = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<Array<{
        id: string;
        hostname: string;
        ip_address: string;
        asset_type: string;
        ports: number[];
        technologies: string[];
        status: string;
        risk_score: number;
        last_scan_at: string | null;
      }>>(`/surface/assets${query}`);
    },
    vulnerabilities: (params?: Record<string, string>) => {
      const query = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<Array<{
        id: string;
        asset_id: string;
        title: string;
        severity: string;
        cvss_score: number | null;
        cve_id: string | null;
        status: string;
        found_at: string;
      }>>(`/surface/vulnerabilities${query}`);
    },
    updateVulnerability: (id: string, data: Record<string, string>) =>
      request(`/surface/vulnerabilities/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
  },

  // Response
  response: {
    incidents: () =>
      request<Array<{
        id: string;
        title: string;
        description: string;
        severity: string;
        status: string;
        source: string;
        mitre_technique: string | null;
        mitre_tactic: string | null;
        source_ip: string | null;
        ai_analysis: Record<string, unknown> | null;
        detected_at: string;
      }>>('/response/incidents'),
    incident: (id: string) =>
      request<{
        id: string;
        title: string;
        description: string;
        severity: string;
        status: string;
        source: string;
        mitre_technique: string | null;
        source_ip: string | null;
        ai_analysis: Record<string, unknown> | null;
        detected_at: string;
        actions: Array<{
          id: string;
          action_type: string;
          target: string;
          status: string;
          requires_approval: boolean;
          ai_reasoning: string | null;
          created_at: string;
        }>;
      }>(`/response/incidents/${id}`),
    actions: () =>
      request<Array<{
        id: string;
        incident_id: string;
        action_type: string;
        target: string;
        status: string;
        requires_approval: boolean;
        ai_reasoning: string | null;
        created_at: string;
      }>>('/response/actions'),
    approveAction: (id: string) =>
      request(`/response/actions/${id}/approve`, { method: 'POST' }),
    guardrails: () =>
      request<Record<string, boolean | string | number>>('/response/guardrails'),
    updateGuardrails: (config: Record<string, boolean | string | number>) =>
      request('/response/guardrails', {
        method: 'PUT',
        body: JSON.stringify(config),
      }),
  },

  // Phantom
  phantom: {
    honeypots: () =>
      request<Array<{
        id: string;
        name: string;
        honeypot_type: string;
        status: string;
        ip_address: string | null;
        port: number | null;
        interactions_count: number;
        last_rotation: string | null;
        created_at: string;
      }>>('/phantom/honeypots'),
    deployHoneypot: (data: { name: string; honeypot_type: string; port: number }) =>
      request('/phantom/honeypots', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    rotateHoneypot: (id: string) =>
      request(`/phantom/honeypots/${id}/rotate`, { method: 'POST' }),
    deleteHoneypot: (id: string) =>
      request(`/phantom/honeypots/${id}`, { method: 'DELETE' }),
    interactions: (params?: Record<string, string>) => {
      const query = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<Array<{
        id: string;
        honeypot_id: string;
        source_ip: string;
        protocol: string;
        commands: string[];
        credentials_tried: Array<{ username: string; password: string }>;
        session_duration: number | null;
        timestamp: string;
      }>>(`/phantom/interactions${query}`);
    },
    attackers: () =>
      request<Array<{
        id: string;
        source_ip: string;
        known_ips: string[];
        tools_used: string[];
        techniques: string[];
        sophistication: string;
        geo_data: { country: string; city: string } | null;
        first_seen: string;
        last_seen: string;
        total_interactions: number;
      }>>('/phantom/attackers'),
  },

  // Threats
  threats: {
    intel: (params?: Record<string, string>) => {
      const query = params ? '?' + new URLSearchParams(params).toString() : '';
      return request<Array<{
        id: string;
        ioc_type: string;
        ioc_value: string;
        threat_type: string;
        confidence: number;
        source: string;
        tags: string[];
        first_seen: string;
        last_seen: string;
      }>>(`/threats/intel${query}`);
    },
    addIOC: (data: { ioc_type: string; ioc_value: string; threat_type: string; source: string; tags: string[] }) =>
      request('/threats/intel', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    search: (query: string) =>
      request<Array<{
        id: string;
        ioc_type: string;
        ioc_value: string;
        threat_type: string;
        confidence: number;
        source: string;
      }>>(`/threats/intel/search?q=${encodeURIComponent(query)}`),
    exportFeed: () => request<Blob>('/threats/feed'),
    sharingStats: () =>
      request<{ iocs_shared: number; iocs_received: number; auto_blocked: number }>('/threats/sharing/stats'),
  },

  // AI Providers
  ai: {
    setActive: (provider: string) =>
      request('/ai/providers/active', {
        method: 'PUT',
        body: JSON.stringify({ provider }),
      }),
    configure: (name: string, config: Record<string, string>) =>
      request(`/ai/providers/${name}/config`, {
        method: 'PUT',
        body: JSON.stringify(config),
      }),
  },

  // Setup
  setup: {
    discover: (target: string) =>
      request<{ assets: Array<{ id: string; hostname: string; ip_address: string; asset_type: string; ports: number[]; status: string }> }>('/setup/discover', {
        method: 'POST',
        body: JSON.stringify({ target }),
      }),
    registerAssets: (assets: Array<{ hostname: string; ip_address: string; asset_type: string }>) =>
      request('/setup/register-assets', {
        method: 'POST',
        body: JSON.stringify({ assets }),
      }),
  },

  // Ask (AI Assistant)
  ask: {
    send: async (message: string, context?: string) => {
      return request<{ answer: string; actions_taken: Record<string, unknown>[]; suggestions: string[]; model_used: string }>('/ask', {
        method: 'POST',
        body: JSON.stringify({ message, context }),
      });
    },
  },

  // Nodes
  nodes: {
    list: () =>
      request<Array<{
        id: string;
        hostname: string;
        os_info: string | null;
        ip_address: string | null;
        agent_version: string;
        status: string;
        last_heartbeat: string | null;
        tags: string[];
        asset_count: number;
        created_at: string | null;
        cpu: number;
        mem: number;
        disk: number;
        processes: number;
        node_type: string | null;
      }>>('/nodes'),
    get: (id: string) =>
      request<{
        id: string;
        hostname: string;
        os_info: string | null;
        ip_address: string | null;
        agent_version: string;
        status: string;
        last_heartbeat: string | null;
        tags: string[];
        asset_count: number;
        created_at: string | null;
        cpu: number;
        mem: number;
        disk: number;
        processes: number;
        node_type: string | null;
      }>(`/nodes/${id}`),
    enroll: (code: string, nodeType?: string) =>
      request<{ status: string; node_id: string; hostname: string; message: string }>('/nodes/enroll', {
        method: 'POST',
        body: JSON.stringify({ code, node_type: nodeType }),
      }),
    remove: (id: string) =>
      request(`/nodes/${id}`, { method: 'DELETE' }),
  },

  // Infra
  infra: {
    systems: () =>
      request<{
        systems: Array<{
          name: string;
          ip: string;
          role: string;
          status: 'online' | 'offline' | 'degraded';
          cpu: number;
          mem: number;
          disk: number;
          uptime: string;
          services: string[];
          pm2_processes: Array<{
            name: string;
            status: string;
            cpu: number;
            mem: string;
            uptime: string;
            restarts: number;
          }>;
        }>;
      }>('/infra/systems'),
    pm2: () =>
      request<{
        processes: Array<{
          name: string;
          status: string;
          cpu: number;
          mem: string;
          uptime: string;
          restarts: number;
        }>;
      }>('/infra/pm2'),
  },

  // Quantum
  quantum: {
    readiness: () => request<{ score: number; quantum_safe_count: number; total_assets: number; last_assessed: string | null }>('/quantum/readiness'),
    timeline: () => request<Array<{ algorithm: string; key_bits: number; type: string; vulnerable_by: number; status: string }>>('/quantum/crypto/timeline'),
    assessAll: () => request<Array<{ algorithm: string; key_bits: number; type: string; classical_security: string; quantum_security: string; status: string; recommendation: string }>>('/quantum/crypto/assess'),
    entropy: (data: string) => request<Array<{ timestamp: string; source: string; renyi_orders: Array<{ alpha: number; entropy: number }>; anomaly_detected: boolean; detection_type: string | null; confidence: number | null }>>('/quantum/entropy', {
      method: 'POST',
      body: JSON.stringify({ data }),
    }),
  },

  // Payments
  payments: {
    status: () =>
      request<{
        current_tier: string;
        max_nodes: number;
        max_assets: number;
        max_users: number;
        upgrades_available: string[];
        prices: Record<string, { price: string; name: string; description: string }>;
        paypal_configured: boolean;
      }>('/payments/status'),
    createOrder: (tier: string) =>
      request<{ order_id: string; approval_url: string | null; tier: string }>('/payments/create-order', {
        method: 'POST',
        body: JSON.stringify({ tier }),
      }),
    captureOrder: (orderId: string) =>
      request<{ status: string; tier: string; transaction_id: string; max_nodes: number; max_assets: number; max_users: number }>('/payments/capture-order', {
        method: 'POST',
        body: JSON.stringify({ order_id: orderId }),
      }),
  },

  // Settings
  settings: {
    client: () =>
      request<{ id: string; name: string; slug: string; api_key: string; settings: Record<string, unknown> }>('/settings/client'),
    updateClient: (data: Record<string, unknown>) =>
      request('/settings/client', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    patchClient: (data: Record<string, unknown>) =>
      request('/settings/client', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    models: () =>
      request<Array<{ task_type: string; model: string; description: string }>>('/settings/models'),
    updateModels: (data: Array<{ task_type: string; model: string }>) =>
      request('/settings/models', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    notifications: () =>
      request<{
        webhook_url: string;
        webhook_format: string;
        email_enabled: boolean;
        email_recipients: string[];
        notify_on_critical: boolean;
        notify_on_high: boolean;
        notify_on_actions: boolean;
        notify_on_scan_completed: boolean;
        telegram_enabled: boolean;
        telegram_bot_token: string;
        telegram_chat_id: string;
        telegram_connected: boolean;
      }>('/settings/notifications'),
    updateNotifications: (data: Record<string, unknown>) =>
      request('/settings/notifications', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    testNotification: (channel: 'telegram' | 'webhook') =>
      request<{ success: boolean; message: string }>('/settings/notifications', {
        method: 'POST',
        body: JSON.stringify({ test: true, channel }),
      }),
    testWebhook: () =>
      request<{ success: boolean; message: string }>('/response/webhook/test', {
        method: 'POST',
      }),
    testModel: (taskType: string, model: string) =>
      request<{ success: boolean; response: string; latency_ms: number }>('/settings/models/test', {
        method: 'POST',
        body: JSON.stringify({ task_type: taskType, model }),
      }),
    updateIntelSharing: (data: { enabled: boolean }) =>
      request('/settings/intel-sharing', {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
  },

  // Compliance
  compliance: {
    frameworks: () =>
      request<{
        frameworks: Array<{
          key: string;
          name: string;
          short_name: string;
          description: string;
          score: number;
          met: number;
          partial: number;
          not_met: number;
          controls: Array<{ id: string; name: string; module: string; status: string; evidence: string }>;
        }>;
        overall_score: number;
        total_controls: number;
        total_met: number;
        total_partial: number;
        total_not_met: number;
        gaps: Array<{ framework: string; control_id: string; control_name: string; evidence: string }>;
        assessed_at: string;
      }>('/compliance/frameworks'),
  },

  // Reports
  reports: {
    types: () =>
      request<Array<{ type: string; name: string; description: string }>>('/reports/types'),
    generate: (reportType: string) => {
      const apiUrl = typeof window !== 'undefined'
        ? localStorage.getItem('aegis_api_url') || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1'
        : 'http://localhost:8000/api/v1';
      const apiKey = typeof window !== 'undefined' ? localStorage.getItem('aegis_api_key') || '' : '';
      const token = typeof window !== 'undefined' ? localStorage.getItem('aegis_token') || '' : '';

      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;
      else if (apiKey) headers['X-API-Key'] = apiKey;

      return fetch(`${apiUrl}/reports/generate`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ report_type: reportType }),
      });
    },
    history: (limit = 20) =>
      request<{ reports: Array<{ id: string; report_type: string; generated_at: string; filename: string; size_bytes: number }>; total: number }>(`/reports/history?limit=${limit}`),
    schedule: () =>
      request<{ status: string; config: Record<string, unknown> }>('/reports/schedule'),
  },

  // Auto-updates
  updates: {
    status: () =>
      request<{
        current_version: string;
        latest_version: string | null;
        update_available: boolean;
        last_checked: string | null;
        last_error: string | null;
        release_notes: string | null;
        release_url: string | null;
        is_updating: boolean;
      }>('/updates/status'),
    check: () =>
      request<{
        current_version: string;
        latest_version: string | null;
        update_available: boolean;
        release_notes: string | null;
        release_url: string | null;
      }>('/updates/check', { method: 'POST' }),
    install: () =>
      request<{ success: boolean; from: string; to: string }>('/updates/install', { method: 'POST' }),
    getConfig: () =>
      request<{ enabled: boolean; check_interval_hours: number; auto_install: boolean; notify_on_available: boolean }>('/updates/config'),
    updateConfig: (cfg: { enabled: boolean; check_interval_hours: number; auto_install: boolean; notify_on_available: boolean }) =>
      request('/updates/config', { method: 'PUT', body: JSON.stringify(cfg) }),
  },

  // Configurable Firewall
  firewall: {
    list: () =>
      request<Array<{
        id: string;
        client_id: string;
        name: string;
        enabled: boolean;
        yaml_def: string;
        priority: number;
        hits: number;
        last_hit_at: string | null;
        created_at: string;
        updated_at: string;
      }>>('/firewall/rules'),
    get: (id: string) =>
      request<{
        id: string;
        client_id: string;
        name: string;
        enabled: boolean;
        yaml_def: string;
        priority: number;
        hits: number;
        last_hit_at: string | null;
        created_at: string;
        updated_at: string;
      }>(`/firewall/rules/${id}`),
    create: (data: { name: string; enabled: boolean; yaml_def: string; priority: number }) =>
      request<{
        id: string;
        client_id: string;
        name: string;
        enabled: boolean;
        yaml_def: string;
        priority: number;
        hits: number;
        last_hit_at: string | null;
        created_at: string;
        updated_at: string;
      }>('/firewall/rules', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    update: (id: string, data: { name?: string; enabled?: boolean; yaml_def?: string; priority?: number }) =>
      request<{
        id: string;
        client_id: string;
        name: string;
        enabled: boolean;
        yaml_def: string;
        priority: number;
        hits: number;
        last_hit_at: string | null;
        created_at: string;
        updated_at: string;
      }>(`/firewall/rules/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
    delete: (id: string) =>
      request(`/firewall/rules/${id}`, { method: 'DELETE' }),
    test: (id: string, event: Record<string, unknown>, yamlDef?: string) =>
      request<{
        ok: boolean;
        matched: boolean;
        structural_match: boolean | null;
        rate_limit: { count: number; window_seconds: number } | null;
        action: string | null;
        rule_name: string | null;
        error: string | null;
      }>(`/firewall/rules/${id}/test`, {
        method: 'POST',
        body: JSON.stringify({ event, yaml_def: yamlDef }),
      }),
    testYaml: (yamlDef: string, event: Record<string, unknown>) =>
      request<{
        ok: boolean;
        matched: boolean;
        structural_match: boolean | null;
        rate_limit: { count: number; window_seconds: number } | null;
        action: string | null;
        rule_name: string | null;
        error: string | null;
      }>('/firewall/test', {
        method: 'POST',
        body: JSON.stringify({ yaml_def: yamlDef, event }),
      }),
    templates: () =>
      request<Array<{
        id: string;
        name: string;
        description: string;
        yaml_def: string;
      }>>('/firewall/templates'),
  },

  // Honey-AI Deception at Scale
  deception: {
    themes: () =>
      request<Array<{
        name: string;
        label: string;
        description: string;
        industry: string;
        bait_kinds: string[];
      }>>('/deception/themes'),
    campaigns: () =>
      request<Array<DeceptionCampaign>>('/deception/campaigns'),
    createCampaign: (body: {
      name: string;
      theme: string;
      decoy_count: number;
      service_mix: { web: number; db: number; files: number; admin: number };
      rotation_hours?: number;
    }) =>
      request<DeceptionCampaign>('/deception/campaigns', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    getCampaign: (id: string) =>
      request<DeceptionCampaign>(`/deception/campaigns/${id}`),
    rotateCampaign: (id: string) =>
      request<DeceptionCampaign>(`/deception/campaigns/${id}/rotate`, {
        method: 'POST',
      }),
    deleteCampaign: (id: string) =>
      request<void>(`/deception/campaigns/${id}`, { method: 'DELETE' }),
    breadcrumbHits: (limit = 50) =>
      request<Array<DeceptionBreadcrumbHit>>(`/deception/breadcrumb-hits?limit=${limit}`),
    breadcrumbs: (campaignId?: string, limit = 100) => {
      const qs = new URLSearchParams();
      if (campaignId) qs.set('campaign_id', campaignId);
      qs.set('limit', String(limit));
      return request<Array<DeceptionBreadcrumbHit>>(`/deception/breadcrumbs?${qs.toString()}`);
    },
  },
};

export interface DeceptionCampaign {
  id: string;
  name: string;
  theme: string;
  decoy_count: number;
  service_mix: { web: number; db: number; files: number; admin: number };
  rotation_hours: number;
  status: string;
  created_at: string;
  deployed_at: string | null;
  last_rotated_at: string | null;
  stopped_at: string | null;
  honeypot_count: number;
  breadcrumb_count: number;
  error: string | null;
}

export interface DeceptionBreadcrumbHit {
  id: string;
  campaign_id: string;
  breadcrumb_uuid: string;
  planted_in: string;
  bait_kind: string;
  hit_count: number;
  last_hit_at: string | null;
  last_hit_source: string | null;
  planted_at: string;
}
