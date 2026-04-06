export const APP_NAME = 'AEGIS';
export const APP_DESCRIPTION = 'Autonomous Cybersecurity Defense Platform';

export const NAV_ITEMS = [
  { label: 'Dashboard', href: '/dashboard', icon: 'LayoutDashboard' },
  { label: 'Surface', href: '/dashboard/surface', icon: 'Radar' },
  { label: 'Response', href: '/dashboard/response', icon: 'ShieldAlert' },
  { label: 'Phantom', href: '/dashboard/phantom', icon: 'Ghost' },
  { label: 'Threats', href: '/dashboard/threats', icon: 'Search' },
  { label: 'Infra', href: '/dashboard/infra', icon: 'Computer' },
  { label: 'Settings', href: '/dashboard/settings', icon: 'Settings' },
] as const;

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const HONEYPOT_TYPES = [
  { value: 'ssh', label: 'SSH', defaultPort: 2222 },
  { value: 'http', label: 'HTTP', defaultPort: 8080 },
  { value: 'smb', label: 'SMB', defaultPort: 445 },
  { value: 'api', label: 'API', defaultPort: 9090 },
  { value: 'database', label: 'Database', defaultPort: 3306 },
  { value: 'smtp', label: 'SMTP', defaultPort: 2525 },
] as const;

export const IOC_TYPES = [
  { value: 'ip', label: 'IP Address' },
  { value: 'domain', label: 'Domain' },
  { value: 'hash', label: 'File Hash' },
  { value: 'url', label: 'URL' },
  { value: 'email', label: 'Email' },
] as const;

export const MODEL_ROUTING_DEFAULTS = [
  { task_type: 'triage', model: 'openrouter/quasar-alpha', description: 'Fast initial triage' },
  { task_type: 'classification', model: 'openrouter/hunter-alpha', description: 'Deep threat classification' },
  { task_type: 'investigation', model: 'openrouter/hunter-alpha', description: 'Complex investigation reasoning' },
  { task_type: 'code_analysis', model: 'openai/gpt-oss-120b:free', description: 'Payload and code analysis' },
  { task_type: 'report', model: 'nvidia/nemotron-3-super-120b-a12b:free', description: 'Report generation' },
  { task_type: 'decoy_content', model: 'minimax/minimax-m2.5:free', description: 'Honeypot content generation' },
  { task_type: 'quick_decision', model: 'stepfun/step-3.5-flash:free', description: 'Sub-second decisions' },
  { task_type: 'risk_scoring', model: 'arcee-ai/trinity-large-preview:free', description: 'Risk assessment scoring' },
  { task_type: 'healing', model: 'openrouter/healer-alpha', description: 'Remediation suggestions' },
  { task_type: 'fallback', model: 'openai/gpt-oss-20b:free', description: 'Lightweight fallback model' },
] as const;

export const CHART_COLORS = {
  cyan: '#00F0FF',
  purple: '#7B61FF',
  danger: '#FF3B5C',
  warning: '#FFB800',
  success: '#00D68F',
  info: '#3B82F6',
};
