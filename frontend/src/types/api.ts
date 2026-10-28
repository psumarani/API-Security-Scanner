export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "confirmed" | "potential" | "informational" | "inconclusive";
export type Confidence = "high" | "medium" | "low";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type AuthType = "none" | "bearer" | "api_key" | "test_account";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const FINDING_STATUSES: FindingStatus[] = ["confirmed", "potential", "informational", "inconclusive"];

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface User {
  id: string;
  username: string;
  email: string;
  role: "user" | "admin";
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_at: string;
}

export interface SessionInfo {
  id: string;
  created_at: string;
  expires_at: string;
  current: boolean;
}

export interface Target {
  id: string;
  name: string;
  base_url: string;
  api_spec_url: string | null;
  authorization_confirmed_at: string;
  authorization_note: string | null;
  allow_local_lab: boolean;
  created_at: string;
  updated_at: string;
}

export interface TargetCreate {
  name: string;
  base_url: string;
  api_spec_url?: string | null;
  authorization_confirmed: boolean;
  authorization_note?: string | null;
  allow_local_lab: boolean;
}

export interface AuthProfile {
  id: string;
  target_id: string;
  name: string;
  auth_type: AuthType;
  role_label: string | null;
  has_credentials: boolean;
  created_at: string;
}

export type AuthConfigInput =
  | { type: "none" }
  | { type: "bearer"; token: string }
  | { type: "api_key"; name: string; location: "header" | "query"; value: string }
  | {
      type: "test_account";
      username: string;
      password: string;
      login_path?: string | null;
      username_field?: string;
      password_field?: string;
      token_field?: string;
    };

export interface AuthProfileCreate {
  name: string;
  role_label?: string | null;
  config: AuthConfigInput;
}

export interface SpecPreview {
  spec_version: string;
  title: string | null;
  endpoint_count: number;
  security_schemes: Record<string, string>;
  base_path_hint: string;
  warnings: string[];
  endpoints: { method: string; path: string; authentication_required: boolean | null; deprecated: boolean; parameters: number }[];
}

export interface ModuleProgress {
  status: string;
  findings: number;
  requests: number;
  notes?: string[];
  inconclusive?: string[];
}

export interface ScanProgress {
  stage?: string;
  current_module?: string | null;
  percent?: number;
  modules?: Record<string, ModuleProgress>;
  notes?: string[];
}

export interface Scan {
  id: string;
  target_id: string;
  target_name: string;
  status: ScanStatus;
  configuration: {
    modules?: string[];
    auth_profiles?: { id: string; name: string; role_label: string | null; auth_type: string }[];
    settings?: Record<string, unknown>;
    scope?: { origin?: string; base_url?: string; spec_url?: string | null; allow_local_lab?: boolean };
  };
  progress: ScanProgress;
  requests_made: number;
  scanner_version: string | null;
  started_at: string | null;
  completed_at: string | null;
  error_summary: string | null;
  created_at: string;
  finding_counts: Partial<Record<Severity, number>>;
  endpoint_count: number;
}

export interface ScanEndpoint {
  id: string;
  path: string;
  http_method: string;
  parameters: unknown[];
  authentication_required: boolean | null;
  discovery_source: string;
  finding_count: number;
}

export interface Finding {
  id: string;
  scan_id: string;
  target_name: string | null;
  endpoint: { id: string; path: string; http_method: string } | null;
  check_id: string;
  category: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  created_at: string;
}

export interface Evidence {
  id: string;
  request_summary: string;
  response_status: number | null;
  response_summary: string;
  observed_at: string;
}

export interface FindingDetail extends Finding {
  description: string;
  remediation: string;
  evidence: Evidence[];
  scan_status: ScanStatus;
  scan_created_at: string;
}

export interface ModuleInfo {
  id: string;
  name: string;
  description: string;
  categories: string[];
  automated: boolean;
  prerequisites: string[];
  validation: string;
  limitations: string;
  default_enabled: boolean;
}

export interface CategoryCoverage {
  category: string;
  title: string;
  support: "supported" | "partial" | "unsupported";
  automation: string;
  modules: string[];
  prerequisites: string;
  validation: string;
  limitations: string;
  evidence: string;
}

export interface ScannerCatalog {
  scanner_version: string;
  modules: ModuleInfo[];
  owasp_coverage: CategoryCoverage[];
  limits: Record<string, { min: number | null; max: number | null; default: number }>;
}

export interface DashboardSummary {
  total_scans: number;
  completed_scans: number;
  running_scans: number;
  failed_scans: number;
  total_findings: number;
  findings_by_severity: Record<Severity, number>;
  findings_by_status: Record<FindingStatus, number>;
  recent_scans: Scan[];
  recent_findings: Finding[];
  recent_failures: { scan_id: string; target_name: string; error_summary: string | null; completed_at: string | null }[];
}

export interface BolaObjectInput { path: string; owner: string }
export interface BflaRuleInput { method: string; path: string; allowed: string[]; forbidden: string[] }

export interface ScanCreate {
  target_id: string;
  modules: string[];
  auth_profile_ids: string[];
  authorization_confirmed: boolean;
  settings: {
    timeout_seconds: number;
    max_requests: number;
    max_concurrency: number;
    max_duration_seconds: number;
    allow_unsafe_methods: boolean;
    sqli: { max_parameters: number };
    rate_limit: { requests: number; concurrency: number; path: string | null };
    bola_objects: BolaObjectInput[];
    bfla_rules: BflaRuleInput[];
  };
}

export interface ApiErrorBody {
  error: { code: string; message: string; details?: { field: string; message: string }[] };
}
