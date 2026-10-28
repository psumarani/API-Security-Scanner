import { api } from "./api";
import type {
  AuthProfile, AuthProfileCreate, DashboardSummary, Finding, FindingDetail, FindingStatus, Page, Scan,
  ScanCreate, ScanEndpoint, ScannerCatalog, ScanStatus, SessionInfo, Severity, SpecPreview, Target,
  TargetCreate, TokenResponse, User,
} from "../types/api";

export const authService = {
  register: (data: { username: string; email: string; password: string }) =>
    api.post<User>("/auth/register", data).then((r) => r.data),
  login: (data: { identifier: string; password: string }) =>
    api.post<TokenResponse>("/auth/login", data).then((r) => r.data),
  logout: () => api.post("/auth/logout"),
  me: () => api.get<User>("/auth/me").then((r) => r.data),
  sessions: () => api.get<SessionInfo[]>("/auth/sessions").then((r) => r.data),
  revokeSession: (id: string) => api.delete(`/auth/sessions/${id}`),
};

export const targetService = {
  list: (limit = 100, offset = 0) =>
    api.get<Page<Target>>("/targets", { params: { limit, offset } }).then((r) => r.data),
  get: (id: string) => api.get<Target>(`/targets/${id}`).then((r) => r.data),
  create: (data: TargetCreate) => api.post<Target>("/targets", data).then((r) => r.data),
  remove: (id: string) => api.delete(`/targets/${id}`),
  specPreview: (id: string) => api.post<SpecPreview>(`/targets/${id}/spec-preview`).then((r) => r.data),
  profiles: (id: string) => api.get<AuthProfile[]>(`/targets/${id}/auth-profiles`).then((r) => r.data),
  createProfile: (id: string, data: AuthProfileCreate) =>
    api.post<AuthProfile>(`/targets/${id}/auth-profiles`, data).then((r) => r.data),
  removeProfile: (id: string, profileId: string) => api.delete(`/targets/${id}/auth-profiles/${profileId}`),
};

export interface FindingQuery {
  limit?: number;
  offset?: number;
  scan_id?: string;
  severity?: Severity[];
  status?: FindingStatus[];
  category?: string;
  search?: string;
}

function paramsOf(query: FindingQuery) {
  const p = new URLSearchParams();
  Object.entries(query).forEach(([k, v]) => {
    if (v === undefined || v === "" || (Array.isArray(v) && v.length === 0)) return;
    if (Array.isArray(v)) v.forEach((x) => p.append(k, String(x)));
    else p.set(k, String(v));
  });
  return p;
}

export const scanService = {
  catalog: () => api.get<ScannerCatalog>("/scanner/catalog").then((r) => r.data),
  dashboard: () => api.get<DashboardSummary>("/dashboard/summary").then((r) => r.data),
  list: (params: { limit?: number; offset?: number; status?: ScanStatus; target_id?: string } = {}) =>
    api.get<Page<Scan>>("/scans", { params }).then((r) => r.data),
  get: (id: string) => api.get<Scan>(`/scans/${id}`).then((r) => r.data),
  create: (data: ScanCreate) => api.post<Scan>("/scans", data).then((r) => r.data),
  cancel: (id: string) => api.post<Scan>(`/scans/${id}/cancel`).then((r) => r.data),
  endpoints: (id: string) => api.get<ScanEndpoint[]>(`/scans/${id}/endpoints`).then((r) => r.data),
  findings: (query: FindingQuery) =>
    api.get<Page<Finding>>("/findings", { params: paramsOf(query) }).then((r) => r.data),
  finding: (id: string) => api.get<FindingDetail>(`/findings/${id}`).then((r) => r.data),
  downloadReport: async (id: string, format: "json" | "html") => {
    const res = await api.get<Blob>(`/scans/${id}/report`, { params: { format }, responseType: "blob" });
    const url = URL.createObjectURL(res.data);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${id}-report.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};
