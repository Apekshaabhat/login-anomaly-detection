export interface AnalysisPayload {
  login_hour: number;
  location_lat: number;
  location_lon: number;
  typing_speed: number;
  failed_attempts: number;
  device_id: string;
  ip_address: string;
  username?: string;
}

export interface AnalysisResponse {
  risk_score: number;
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reasons: string[];
  attack_type: string;
  explanation?: string;
  decision?: string;
  verification_token?: string | null;
  debug_otp?: string | null;
  access_token?: string | null;
  refresh_token?: string | null;
  token_type?: string;
  login_attempt_id?: number | null;
  ip_address?: string | null;
  mfa_required?: boolean;
  mfa_method?: string | null;
  new_device?: boolean;
  new_ip?: boolean;
  device_approval_status?: string | null;
  approval_required?: boolean;
  challenge_state?: string | null;
  captcha_required?: boolean;
  fraud_probability?: number;
  session_trust_score?: number;
  recommended_action?: string | null;
}

export interface LoginRequestPayload extends AnalysisPayload {
  username: string;
  password: string;
  remember_device?: boolean;
  browser?: string | null;
  os?: string | null;
  device_type?: string | null;
  screen_resolution?: string | null;
  timezone?: string | null;
  language?: string | null;
  hardware_fingerprint?: string | null;
  user_agent_hash?: string | null;
  device_nickname?: string | null;
}

export interface DashboardLog {
  id: number;
  user: string;
  time: string;
  location: string;
  device: string;
  risk: number;
  status: "safe" | "suspicious" | "blocked";
  ip_address: string;
  location_lat?: number | null;
  location_lon?: number | null;
  reasons: string[];
  mfa_required: boolean;
  mfa_method?: string | null;
  mfa_verified_at?: string | null;
  new_device: boolean;
  new_ip: boolean;
  device_approval_status?: string | null;
}

export interface DashboardResponse {
  logs: DashboardLog[];
  timeline: Array<{ time: string; risk: number; baseline: number }>;
  distribution: Array<{ name: string; value: number }>;
}

export interface AdminAlert {
  id: number;
  user_id: number | null;
  username: string;
  login_attempt_id: number | null;
  time: string;
  message: string;
  severity: "low" | "medium" | "high" | "critical";
  attack_type: string;
  resolved: boolean;
  requires_manual_action: boolean;
  auto_action: string | null;
}

export interface DeviceRecord {
  id: number;
  user_id?: number;
  username?: string;
  fingerprint: string;
  nickname?: string | null;
  browser?: string | null;
  os?: string | null;
  device_type?: string | null;
  screen_resolution?: string | null;
  timezone?: string | null;
  language?: string | null;
  hardware_fingerprint?: string | null;
  user_agent_hash?: string | null;
  state?: "trusted" | "pending_verification" | "blocked" | "suspicious" | string;
  is_trusted: boolean;
  remember_device?: boolean;
  first_ip_address?: string | null;
  last_ip_address?: string | null;
  approval_status: "pending" | "approved" | "denied" | string;
  approved_at?: string | null;
  last_mfa_method?: string | null;
  first_seen: string;
  last_seen: string;
}

export interface SecurityHistoryItem {
  id: number;
  timestamp: string;
  ip_address: string;
  location_lat?: number | null;
  location_lon?: number | null;
  country?: string | null;
  city?: string | null;
  device_fingerprint: string;
  success: boolean;
  risk_score: number;
  decision: string;
  reasons: string[];
  mfa_required: boolean;
  mfa_method?: string | null;
  mfa_verified_at?: string | null;
  new_device: boolean;
  new_ip: boolean;
  device_approval_status?: string | null;
  ip_risk_score?: number | null;
  asn?: string | null;
  provider?: string | null;
  is_vpn?: boolean;
  is_proxy?: boolean;
  is_tor?: boolean;
}

export interface SecurityAlertItem {
  id: string;
  source: "alert" | "notification";
  time: string;
  message: string;
  severity: "low" | "medium" | "high" | "critical" | string;
  status: string;
  type: string;
}

export interface SessionRecord {
  id: number;
  ip_address?: string | null;
  device_fingerprint?: string | null;
  user_agent_hash?: string | null;
  created_at: string;
  last_used_at?: string | null;
  expires_at: string;
  revoked_at?: string | null;
  active: boolean;
}

export interface AdminAnalytics {
  live_login_attempts: number;
  active_alerts: number;
  attack_source_countries: Array<{ country: string; attempts: number }>;
  device_trust_statistics: Record<string, number>;
  risk_score_distribution: Record<string, number>;
  mfa_metrics: { required: number; success: number; failure: number };
  suspicious_ip_leaderboard: Array<{ ip_address: string; reason: string; severity: string }>;
  real_time_alerts: AdminAlert[];
}

export interface BehaviorTelemetryPayload {
  session_id: string;
  device_fingerprint?: string | null;
  ip_address?: string | null;
  page_path?: string | null;
  typing_speed?: number | null;
  typing_variance?: number | null;
  key_hold_mean?: number | null;
  key_flight_mean?: number | null;
  correction_rate?: number | null;
  mouse_velocity_mean?: number | null;
  mouse_velocity_std?: number | null;
  mouse_idle_ratio?: number | null;
  scroll_depth?: number | null;
  scroll_velocity_mean?: number | null;
  replay_event_count?: number;
  replay_anomaly_score?: number | null;
  focus_change_count?: number;
  active_seconds?: number;
  extra?: Record<string, unknown>;
}

export interface AISecurityDashboard {
  attack_monitoring: {
    total_attempts: number;
    blocked: number;
    mfa_triggered: number;
    high_risk: number;
  };
  suspicious_sessions: Array<{
    session_id: string;
    user_id: number;
    risk_score: number;
    trust_score: number;
    decision: string;
    reasons: string[];
    time: string;
  }>;
  risk_analytics: {
    average_risk: number;
    average_session_trust: number;
    fraud_probability: number;
  };
  login_heatmap: Array<{ country: string; attempts: number }>;
  anomaly_timeline: Array<{ time: string; risk: number }>;
  trust_score_trends: Array<{ time: string; trust: number }>;
  behavioral_biometrics: {
    events: number;
    average_anomaly: number;
    average_trust: number;
  };
  alerts: Array<{ id: number; severity: string; message: string; attack_type?: string | null; time: string }>;
  enterprise_capabilities?: EnterpriseCapabilities;
  ml_strategy?: {
    active: string;
    upgrade_ready: string[];
    signals: string[];
  };
}

export interface IntegrationItem {
  name: string;
  configured: boolean;
  capability: string;
}

export interface EnterpriseCapabilities {
  threat_intelligence: IntegrationItem[];
  authentication_mfa: IntegrationItem[];
  notifications: IntegrationItem[];
  device_behavior: IntegrationItem[];
}

export interface ThreatIntelResponse {
  indicator?: string;
  indicator_type?: string;
  risk_score: number;
  verdict: string;
  summary?: string;
  providers?: Array<{ provider: string; risk_score: number; verdict: string; summary: string }>;
}

export interface PasswordBreachResponse {
  breached: boolean;
  breach_count: number;
  risk_score: number;
  verdict: string;
  provider: string;
  provider_status: string;
  attribution: string;
}

export interface BehaviorResponse {
  username: string;
  is_new_user: boolean;
  typical_login_time: string;
  frequent_locations: string[];
  devices_used: string[];
  trust_score: number;
  trend_data: Array<{
    label: string;
    login_count: number;
    avg_typing_speed: number;
    failed_attempts: number;
  }>;
  comparison_data: Array<{
    axis: string;
    normal: number;
    current: number;
  }>;
  trust_history: Array<{
    date: string;
    score: number;
  }>;
  failed_attempts: number;
}

export interface ModelStatusResponse {
  model_name: string;
  active_model_key: string;
  available_models: ModelRegistryItem[];
  version: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc: number;
  false_positive_rate: number;
  confusion_matrix: ModelConfusionMatrixResponse;
  inference_time_ms: number;
  dataset_size: number;
  last_trained: string;
  drift_detected: boolean;
  drift_score: number;
  status: "healthy" | "degraded" | "unavailable";
}

export interface ModelRegistryItem {
  key: string;
  name: string;
  available: boolean;
}

export interface ModelRegistryResponse {
  default_model: string;
  models: ModelRegistryItem[];
}

export interface ModelConfusionMatrixResponse {
  labels: ["normal", "anomaly"] | string[];
  matrix: number[][];
  counts: {
    tn: number;
    fp: number;
    fn: number;
    tp: number;
  };
  total: number;
  generated_at: string;
}

export interface ModelDriftResponse {
  drift_detected: boolean;
  drift_level?: "low" | "moderate" | "high" | "critical";
  drift_score: number;
  affected_features: Array<{
    feature: string;
    score: number;
    psi?: number;
    kl_divergence?: number;
  }>;
  timestamp: string;
}

export interface ModelRetrainResponse {
  success: boolean;
  new_version: string;
  training_samples: number;
  training_time_seconds: number;
  metrics: Record<string, number>;
}

export interface ModelHistoryItem {
  version: string;
  trained_at: string;
  dataset_size: number;
  accuracy: number;
}

export interface ModelExplainResponse {
  risk_score: number;
  top_factors: Array<{
    feature: string;
    impact: number;
    description?: string;
  }>;
  explanation: string;
}

export interface ModelMonitoringResponse {
  status: string;
  total_predictions: number;
  average_latency_ms: number;
  p95_latency_ms: number;
  anomaly_rate: number;
  recent_prediction_count: number;
  recent_block_rate: number;
  timestamp: string;
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const accessToken = typeof window !== "undefined" ? window.localStorage.getItem("access_token") : null;
  const csrfToken = typeof document !== "undefined"
    ? document.cookie
        .split("; ")
        .find((row) => row.startsWith("csrf_token="))
        ?.split("=")[1]
    : null;
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...(csrfToken ? { "X-CSRF-Token": decodeURIComponent(csrfToken) } : {}),
      ...(init?.headers ?? {}),
    },
    credentials: "include",
    ...init,
  });

  if (!response.ok) {
    let message = "Something went wrong while contacting the server.";
    try {
      const payload = await response.json();
      message = payload.detail ?? payload.message ?? message;
    } catch {
      // Fall back to a generic message when the server response is not JSON.
    }
    if (response.status === 401 && typeof window !== "undefined") {
      window.localStorage.removeItem("access_token");
      window.localStorage.removeItem("refresh_token");
      message = message === "Authentication required" ? "Please sign in to continue." : message;
    }
    throw new Error(message);
  }

  return response.json() as Promise<T>;
}

const getAdminToken = (adminToken?: string) =>
  adminToken || import.meta.env.VITE_ADMIN_SECRET_TOKEN || "";

export function analyzeLogin(payload: AnalysisPayload) {
  return requestJson<AnalysisResponse>("/api/auth/analyze", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function loginRequest(payload: LoginRequestPayload) {
  return requestJson<AnalysisResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function verifyOtp(username: string, otp: string, verificationToken: string) {
  return requestJson<{
    message: string;
    access_token?: string;
    refresh_token?: string;
    mfa_method?: string | null;
    login_attempt_id?: number | null;
    challenge_state?: string;
    approval_required?: boolean;
  }>(
    "/api/auth/verify-otp",
    {
      method: "POST",
      body: JSON.stringify({
        username,
        otp,
        verification_token: verificationToken,
      }),
    },
  );
}

export function resendOtp(verificationToken: string) {
  return requestJson<{ message: string; resend_available_at: string }>("/api/auth/resend-otp", {
    method: "POST",
    body: JSON.stringify({ verification_token: verificationToken }),
  });
}

export function fetchChallengeStatus(verificationToken: string) {
  return requestJson<{
    challenge_state: string;
    approval_required?: boolean;
    device_approved?: boolean;
    otp_verified?: boolean;
    expires_at?: string;
    access_token?: string;
    refresh_token?: string;
    token_type?: string;
  }>(`/api/auth/challenge/${encodeURIComponent(verificationToken)}`);
}

export function approveDeviceLogin(approvalToken: string) {
  return requestJson<{ message: string; status: string; challenge_token?: string }>("/api/auth/approve-device", {
    method: "POST",
    body: JSON.stringify({ approval_token: approvalToken }),
  });
}

export function denyDeviceLogin(approvalToken: string) {
  return requestJson<{ message: string; status: string; challenge_token?: string }>("/api/auth/deny-device", {
    method: "POST",
    body: JSON.stringify({ approval_token: approvalToken }),
  });
}

export function refreshSession(refreshToken?: string) {
  return requestJson<{ access_token: string; refresh_token: string; token_type: string }>("/api/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
}

export function logoutRequest(refreshToken?: string) {
  return requestJson<{ message: string }>("/api/auth/logout", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
}

export function fetchDashboard() {
  return requestJson<DashboardResponse>("/api/admin/dashboard");
}

export function fetchBehavior(username: string) {
  return requestJson<BehaviorResponse>(`/api/admin/behavior/${encodeURIComponent(username)}`);
}

export function fetchAlerts() {
  return requestJson<AdminAlert[]>("/api/admin/alerts");
}

export function fetchDevices() {
  return requestJson<DeviceRecord[]>("/api/admin/devices");
}

export function fetchUserDevices() {
  return requestJson<DeviceRecord[]>("/api/devices");
}

export function trustUserDevice(deviceId: number, nickname?: string) {
  return requestJson<{ message: string; device: DeviceRecord }>("/api/devices/trust", {
    method: "POST",
    body: JSON.stringify({ device_id: deviceId, nickname, remember_device: true }),
  });
}

export function revokeUserDevice(deviceId: number) {
  return requestJson<{ message: string }>(`/api/devices/${deviceId}`, {
    method: "DELETE",
  });
}

export function fetchSecurityHistory() {
  return requestJson<SecurityHistoryItem[]>("/api/security/history");
}

export function fetchSecurityAlerts() {
  return requestJson<SecurityAlertItem[]>("/api/security/alerts");
}

export function fetchSecuritySessions() {
  return requestJson<SessionRecord[]>("/api/security/sessions");
}

export function fetchAdminAnalytics() {
  return requestJson<AdminAnalytics>("/api/admin/analytics");
}

export function sendBehaviorTelemetry(payload: BehaviorTelemetryPayload) {
  return requestJson<{
    telemetry_id: number;
    behavior_anomaly_score: number;
    trust_score: number;
    session_risk_score: number;
    session_trust_score: number;
    fraud_probability: number;
    decision: string;
    recommended_action: string;
    reasons: string[];
  }>("/api/ai/telemetry", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function fetchAISecurityDashboard() {
  return requestJson<AISecurityDashboard>("/api/ai/dashboard");
}

export function fetchAIIntegrations() {
  return requestJson<EnterpriseCapabilities>("/api/ai/integrations");
}

export function fetchThreatIntel(ipAddress: string) {
  return requestJson<ThreatIntelResponse>(`/api/ai/threat-intel/ip/${encodeURIComponent(ipAddress)}`);
}

export function checkPwnedPassword(password: string) {
  return requestJson<PasswordBreachResponse>("/api/ai/threat-intel/password", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export function approveDevice(deviceId: number, adminToken?: string) {
  return requestJson<{ message: string; device: DeviceRecord }>(`/api/admin/devices/${deviceId}/approve`, {
    method: "POST",
    body: JSON.stringify({ admin_token: getAdminToken(adminToken) }),
  });
}

export function resolveAlert(alertId: number, adminToken?: string) {
  return requestJson<{ message: string }>(`/api/admin/alerts/${alertId}/resolve`, {
    method: "POST",
    body: JSON.stringify({ admin_token: getAdminToken(adminToken) }),
  });
}

export function blockAlert(alertId: number, adminToken?: string) {
  return requestJson<{ message: string }>(`/api/admin/alerts/${alertId}/block`, {
    method: "POST",
    body: JSON.stringify({ admin_token: getAdminToken(adminToken) }),
  });
}

export function generateLiveSimulation(count = 5) {
  return requestJson<{ generated: number }>("/api/simulation/live/generate", {
    method: "POST",
    body: JSON.stringify({ count }),
  });
}

export function fetchModelStatus() {
  return requestJson<ModelStatusResponse>("/api/model/status");
}

export function fetchModelDrift() {
  return requestJson<ModelDriftResponse>("/api/model/drift");
}

export function retrainModel() {
  return requestJson<ModelRetrainResponse>("/api/model/retrain", {
    method: "POST",
  });
}

export function fetchModelHistory() {
  return requestJson<ModelHistoryItem[]>("/api/model/history");
}

export function explainModel(loginFeatures: Record<string, number | string>) {
  return requestJson<ModelExplainResponse>("/api/model/explain", {
    method: "POST",
    body: JSON.stringify({ login_features: loginFeatures }),
  });
}

export function fetchModelMonitoring() {
  return requestJson<ModelMonitoringResponse>("/api/model/monitoring");
}

export function fetchModelConfusionMatrix() {
  return requestJson<ModelConfusionMatrixResponse>("/api/model/confusion-matrix");
}

export function fetchModelRegistry() {
  return requestJson<ModelRegistryResponse>("/api/model/registry");
}
