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
  level: "LOW" | "MEDIUM" | "HIGH";
  reasons: string[];
  attack_type: string;
  explanation?: string;
  decision?: string;
  verification_token?: string | null;
  debug_otp?: string | null;
}

export interface LoginRequestPayload extends AnalysisPayload {
  username: string;
  password: string;
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
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
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
    throw new Error(message);
  }

  return response.json() as Promise<T>;
}

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
  return requestJson<{ message: string }>("/api/auth/verify", {
    method: "POST",
    body: JSON.stringify({
      username,
      otp,
      verification_token: verificationToken,
    }),
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

export function resolveAlert(alertId: number, adminToken = "admin_secret") {
  return requestJson<{ message: string }>(`/api/admin/alerts/${alertId}/resolve`, {
    method: "POST",
    body: JSON.stringify({ admin_token: adminToken }),
  });
}

export function blockAlert(alertId: number, adminToken = "admin_secret") {
  return requestJson<{ message: string }>(`/api/admin/alerts/${alertId}/block`, {
    method: "POST",
    body: JSON.stringify({ admin_token: adminToken }),
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
