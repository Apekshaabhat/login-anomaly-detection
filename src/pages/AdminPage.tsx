import { useEffect, useMemo, useState } from "react";
import { Bell, Check, Monitor, Settings, Shield, Slash } from "lucide-react";

import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/sonner";
import {
  approveDevice,
  blockAlert,
  fetchAdminAnalytics,
  fetchAlerts,
  fetchDevices,
  generateLiveSimulation,
  resolveAlert,
  type AdminAnalytics,
  type AdminAlert,
  type DeviceRecord,
} from "@/lib/api";

function formatMfaMethod(method?: string | null) {
  if (method === "email_otp") return "Email OTP";
  if (method === "sms_otp") return "SMS OTP";
  return "None";
}

export default function AdminPage() {
  const [threshold, setThreshold] = useState(65);
  const [alerts, setAlerts] = useState<AdminAlert[]>([]);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [analytics, setAnalytics] = useState<AdminAnalytics | null>(null);
  const [simulating, setSimulating] = useState(true);

  const refreshAlerts = async () => {
    try {
      const data = await fetchAlerts();
      setAlerts(data);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to load alerts.");
    }
  };

  const refreshDevices = async () => {
    try {
      const data = await fetchDevices();
      setDevices(data);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to load devices.");
    }
  };

  const refreshAnalytics = async () => {
    try {
      setAnalytics(await fetchAdminAnalytics());
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to load admin analytics.");
    }
  };

  useEffect(() => {
    void refreshAlerts();
    void refreshDevices();
    void refreshAnalytics();
  }, []);

  useEffect(() => {
    if (!simulating) return;

    const intervalId = window.setInterval(async () => {
      try {
        await generateLiveSimulation(2);
        await refreshAlerts();
        await refreshDevices();
        await refreshAnalytics();
      } catch (error) {
        toast.error(error instanceof Error ? error.message : "Live simulation failed.");
      }
    }, 10000);

    return () => window.clearInterval(intervalId);
  }, [simulating]);

  const resolve = async (id: number) => {
    try {
      await resolveAlert(id);
      await refreshAlerts();
      toast.success("Alert resolved.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to resolve alert.");
    }
  };

  const manualBlock = async (id: number) => {
    try {
      await blockAlert(id);
      await refreshAlerts();
      toast.success("User blocked from alert.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to block from alert.");
    }
  };

  const approveTrackedDevice = async (id: number) => {
    try {
      await approveDevice(id);
      await refreshDevices();
      toast.success("Device approved.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to approve device.");
    }
  };

  const severityColor: Record<string, string> = {
    low: "bg-success/10 text-success",
    medium: "bg-warning/10 text-warning",
    high: "bg-destructive/10 text-destructive",
    critical: "bg-destructive/20 text-destructive",
  };

  const approvalColor: Record<string, string> = {
    pending: "bg-warning/10 text-warning",
    approved: "bg-success/10 text-success",
    denied: "bg-destructive/10 text-destructive",
  };

  const stateColor = (state?: string) => {
    if (state === "trusted") return "bg-success/10 text-success";
    if (state === "blocked") return "bg-destructive/10 text-destructive";
    if (state === "suspicious") return "bg-warning/10 text-warning";
    if (state === "pending_verification") return "bg-warning/10 text-warning";
    return undefined;
  };

  const liveAlerts = useMemo(() => alerts.filter((alert) => !alert.resolved), [alerts]);
  const resolvedAlerts = useMemo(() => alerts.filter((alert) => alert.resolved), [alerts]);

  return (
    <div className="space-y-5 animate-slide-up">
      <h1 className="text-xl font-bold flex items-center gap-2">
        <Settings className="w-5 h-5 text-primary" /> Admin Control Panel
      </h1>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <GlassCard>
          <p className="text-xs text-muted-foreground">Login attempts</p>
          <p className="text-2xl font-bold font-mono">{analytics?.live_login_attempts ?? 0}</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground">Active alerts</p>
          <p className="text-2xl font-bold font-mono text-warning">{analytics?.active_alerts ?? liveAlerts.length}</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground">MFA success</p>
          <p className="text-2xl font-bold font-mono text-success">{analytics?.mfa_metrics.success ?? 0}</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground">Suspicious IPs</p>
          <p className="text-2xl font-bold font-mono text-destructive">{analytics?.suspicious_ip_leaderboard.length ?? 0}</p>
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <GlassCard glow>
          <h3 className="text-sm font-semibold mb-4">Live Simulation Controls</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Simulation Status</span>
              <span className="font-mono text-lg font-bold text-primary">{simulating ? "LIVE" : "PAUSED"}</span>
            </div>
            <div className="flex gap-2">
              <Button size="sm" onClick={() => setSimulating((value) => !value)}>
                {simulating ? "Pause Stream" : "Resume Stream"}
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  void generateLiveSimulation(6).then(async () => {
                    await refreshAlerts();
                    await refreshDevices();
                    await refreshAnalytics();
                  })
                }
              >
                Generate Burst
              </Button>
            </div>
            <div className="space-y-4 pt-2 border-t border-border/40">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Severity Threshold</span>
                <span className="font-mono text-lg font-bold text-primary">{threshold}%</span>
              </div>
              <input
                type="range"
                min={10}
                max={95}
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
                className="w-full h-2 rounded-full appearance-none cursor-pointer bg-secondary [&::-webkit-slider-thumb]:w-5 [&::-webkit-slider-thumb]:h-5 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-primary [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:shadow-lg"
              />
              <div className="text-xs text-muted-foreground">
                Medium and high alerts support manual blocking. Critical alerts are auto-blocked.
              </div>
            </div>
          </div>
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Monitor className="w-4 h-4" /> Trusted Devices
          </h3>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {devices.length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-4">No tracked devices yet</p>
            )}
            {devices.map((device) => (
              <div key={device.id} className="p-2.5 rounded-lg bg-secondary/30 text-sm space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium">{device.username}</p>
                    <p className="text-xs text-muted-foreground truncate">{device.fingerprint}</p>
                  </div>
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${
                      approvalColor[device.approval_status] ?? stateColor(device.state) ?? "bg-secondary text-muted-foreground"
                    }`}
                  >
                    {device.state ?? device.approval_status}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                  <span className="font-mono truncate">IP {device.last_ip_address ?? "unknown"}</span>
                  <span>{formatMfaMethod(device.last_mfa_method)}</span>
                </div>
                {device.approval_status === "pending" && (
                  <Button size="sm" variant="outline" className="w-full text-xs" onClick={() => void approveTrackedDevice(device.id)}>
                    <Check className="w-3.5 h-3.5 mr-1.5" /> Approve
                  </Button>
                )}
              </div>
            ))}
          </div>
        </GlassCard>

        <GlassCard className="border-destructive/20 lg:col-span-2">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Bell className="w-4 h-4 text-destructive" /> Live Alerts
            {liveAlerts.length > 0 && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-destructive/10 text-destructive font-mono">
                {liveAlerts.length}
              </span>
            )}
          </h3>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {liveAlerts.length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-4">No active alerts</p>
            )}
            {liveAlerts.map((alert) => (
              <div key={alert.id} className="flex items-start gap-3 p-2.5 rounded-lg bg-secondary/30 animate-fade-in">
                <Shield className="w-4 h-4 text-destructive mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm">{alert.message}</p>
                  <p className="text-xs text-muted-foreground">
                    {alert.username} - {new Date(alert.time).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </p>
                  <p className="text-xs text-muted-foreground">Attack Type: {alert.attack_type}</p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${severityColor[alert.severity]}`}>
                  {alert.severity}
                </span>
                {alert.requires_manual_action && (
                  <button
                    onClick={() => void manualBlock(alert.id)}
                    className="text-muted-foreground hover:text-destructive transition-colors shrink-0"
                    title="Manually block user"
                  >
                    <Slash className="w-4 h-4" />
                  </button>
                )}
                <button
                  onClick={() => void resolve(alert.id)}
                  className="text-muted-foreground hover:text-success transition-colors shrink-0"
                  title="Resolve alert"
                >
                  <Check className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </GlassCard>
      </div>

      <GlassCard>
        <h3 className="text-sm font-semibold mb-3">Alert History</h3>
        <div className="space-y-1.5 max-h-48 overflow-y-auto">
          {resolvedAlerts.map((alert) => (
            <div key={alert.id} className="flex items-center gap-3 p-2 rounded-lg text-sm text-muted-foreground">
              <Check className="w-3.5 h-3.5 text-success shrink-0" />
              <span className="flex-1">{alert.message}</span>
              <span className={`text-xs px-2 py-0.5 rounded-full ${severityColor[alert.severity]}`}>
                {alert.severity}
              </span>
              <span className="text-xs">
                {new Date(alert.time).toLocaleString([], { month: "short", day: "numeric" })}
              </span>
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}
