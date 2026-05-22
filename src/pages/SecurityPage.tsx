import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Clock, Globe2, KeyRound, Lock, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import LoginMap from "@/components/LoginMap";
import { useAuthStore } from "@/lib/auth-store";
import {
  fetchSecurityAlerts,
  fetchSecurityHistory,
  fetchSecuritySessions,
  type DashboardLog,
  type SecurityHistoryItem,
} from "@/lib/api";

function formatMfaMethod(method?: string | null) {
  if (method === "email_otp") return "Email OTP";
  if (method === "totp_or_email") return "Authenticator or Email";
  return method ?? "None";
}

function historyToMapLog(item: SecurityHistoryItem): DashboardLog {
  return {
    id: item.id,
    user: "You",
    time: item.timestamp,
    location: [item.city, item.country].filter(Boolean).join(", ") || "Unknown",
    device: item.device_fingerprint,
    risk: Math.round(item.risk_score || 0),
    status: item.decision === "block" ? "blocked" : item.risk_score >= 40 ? "suspicious" : "safe",
    ip_address: item.ip_address,
    location_lat: item.location_lat,
    location_lon: item.location_lon,
    reasons: item.reasons,
    mfa_required: item.mfa_required,
    mfa_method: item.mfa_method,
    mfa_verified_at: item.mfa_verified_at,
    new_device: item.new_device,
    new_ip: item.new_ip,
    device_approval_status: item.device_approval_status,
  };
}

export default function SecurityPage() {
  const { isAuthenticated } = useAuthStore();
  const historyQuery = useQuery({ queryKey: ["security-history"], queryFn: fetchSecurityHistory, enabled: isAuthenticated });
  const alertsQuery = useQuery({ queryKey: ["security-alerts"], queryFn: fetchSecurityAlerts, enabled: isAuthenticated });
  const sessionsQuery = useQuery({ queryKey: ["security-sessions"], queryFn: fetchSecuritySessions, enabled: isAuthenticated });

  const history = historyQuery.data ?? [];
  const alerts = alertsQuery.data ?? [];
  const sessions = sessionsQuery.data ?? [];
  const activeSessions = sessions.filter((session) => session.active);
  const mapLogs = history.map(historyToMapLog);

  if (!isAuthenticated) {
    return (
      <div className="space-y-5 animate-slide-up">
        <div>
          <h1 className="text-xl font-bold">Account Security</h1>
          <p className="text-sm text-muted-foreground">Sign in to view login history, alerts, active sessions, and location activity.</p>
        </div>
        <GlassCard className="max-w-xl">
          <div className="flex items-start gap-3">
            <Lock className="w-5 h-5 text-primary mt-0.5" />
            <div className="space-y-3">
              <div>
                <p className="font-medium">Authentication required</p>
                <p className="text-sm text-muted-foreground">Security Center data is only available after a successful login.</p>
              </div>
              <Button asChild size="sm">
                <Link to="/">Go to login</Link>
              </Button>
            </div>
          </div>
        </GlassCard>
      </div>
    );
  }

  return (
    <div className="space-y-5 animate-slide-up">
      <div>
        <h1 className="text-xl font-bold">Account Security</h1>
        <p className="text-sm text-muted-foreground">Login history, alerts, active sessions, and location activity for your account.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <GlassCard>
          <p className="text-xs text-muted-foreground flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" /> Logins</p>
          <p className="text-2xl font-bold font-mono">{history.length}</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" /> Alerts</p>
          <p className="text-2xl font-bold font-mono">{alerts.length}</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground flex items-center gap-1.5"><KeyRound className="w-3.5 h-3.5" /> Active Sessions</p>
          <p className="text-2xl font-bold font-mono">{activeSessions.length}</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> MFA Success</p>
          <p className="text-2xl font-bold font-mono">{history.filter((item) => item.mfa_verified_at).length}</p>
        </GlassCard>
      </div>

      <GlassCard>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Globe2 className="w-4 h-4" /> Login Locations</h3>
        <div className="rounded-xl overflow-hidden border border-border/30">
          <LoginMap logs={mapLogs} />
        </div>
      </GlassCard>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <GlassCard className="xl:col-span-2 overflow-x-auto">
          <h3 className="text-sm font-semibold mb-3">Login History</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/50 text-xs text-muted-foreground">
                <th className="text-left py-2 px-3 font-medium">Time</th>
                <th className="text-left py-2 px-3 font-medium">IP</th>
                <th className="text-left py-2 px-3 font-medium hidden md:table-cell">Location</th>
                <th className="text-left py-2 px-3 font-medium">Risk</th>
                <th className="text-left py-2 px-3 font-medium hidden lg:table-cell">MFA</th>
                <th className="text-left py-2 px-3 font-medium">Decision</th>
              </tr>
            </thead>
            <tbody>
              {history.slice(0, 30).map((item) => (
                <tr key={item.id} className="border-b border-border/20 hover:bg-secondary/30 transition-colors">
                  <td className="py-2.5 px-3 text-xs text-muted-foreground">
                    {new Date(item.timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-xs">{item.ip_address}</td>
                  <td className="py-2.5 px-3 hidden md:table-cell text-xs text-muted-foreground">
                    {[item.city, item.country].filter(Boolean).join(", ") || "Unknown"}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-xs">{Math.round(item.risk_score)}%</td>
                  <td className="py-2.5 px-3 hidden lg:table-cell text-xs text-muted-foreground">{formatMfaMethod(item.mfa_method)}</td>
                  <td className="py-2.5 px-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${item.decision === "block" ? "bg-destructive/10 text-destructive" : item.decision === "require_verification" ? "bg-warning/10 text-warning" : "bg-success/10 text-success"}`}>
                      {item.decision}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </GlassCard>

        <div className="space-y-4">
          <GlassCard>
            <h3 className="text-sm font-semibold mb-3">Security Alerts</h3>
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {alerts.slice(0, 12).map((alert) => (
                <div key={alert.id} className="p-2.5 rounded-lg bg-secondary/30">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-sm">{alert.message}</p>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-warning/10 text-warning">{alert.severity}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {new Date(alert.time).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </p>
                </div>
              ))}
              {alerts.length === 0 && <p className="text-sm text-muted-foreground text-center py-5">No alerts for this account.</p>}
            </div>
          </GlassCard>

          <GlassCard>
            <h3 className="text-sm font-semibold mb-3">Active Sessions</h3>
            <div className="space-y-2 max-h-72 overflow-y-auto">
              {sessions.slice(0, 12).map((session) => (
                <div key={session.id} className="p-2.5 rounded-lg bg-secondary/30">
                  <div className="flex items-center justify-between gap-2">
                    <p className="font-mono text-xs truncate">{session.ip_address ?? "unknown IP"}</p>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${session.active ? "bg-success/10 text-success" : "bg-secondary text-muted-foreground"}`}>
                      {session.active ? "active" : "ended"}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    Created {new Date(session.created_at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </p>
                </div>
              ))}
              {sessions.length === 0 && <p className="text-sm text-muted-foreground text-center py-5">No sessions recorded yet.</p>}
            </div>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}
