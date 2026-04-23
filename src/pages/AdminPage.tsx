import { useEffect, useMemo, useState } from "react";
import { Bell, Check, Monitor, Settings, Shield, Slash, X } from "lucide-react";

import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "@/components/ui/sonner";
import { blockAlert, fetchAlerts, generateLiveSimulation, resolveAlert, type AdminAlert } from "@/lib/api";

export default function AdminPage() {
  const [threshold, setThreshold] = useState(65);
  const [alerts, setAlerts] = useState<AdminAlert[]>([]);
  const [trustedDevices, setTrustedDevices] = useState(["Chrome / Windows 11", "Safari / macOS 14"]);
  const [newDevice, setNewDevice] = useState("");
  const [simulating, setSimulating] = useState(true);

  const refreshAlerts = async () => {
    try {
      const data = await fetchAlerts();
      setAlerts(data);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to load alerts.");
    }
  };

  useEffect(() => {
    void refreshAlerts();
  }, []);

  useEffect(() => {
    if (!simulating) return;

    const intervalId = window.setInterval(async () => {
      try {
        await generateLiveSimulation(2);
        await refreshAlerts();
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

  const severityColor: Record<string, string> = {
    low: "bg-success/10 text-success",
    medium: "bg-warning/10 text-warning",
    high: "bg-destructive/10 text-destructive",
    critical: "bg-destructive/20 text-destructive",
  };

  const addDevice = () => {
    if (newDevice.trim() && !trustedDevices.includes(newDevice.trim())) {
      setTrustedDevices((prev) => [...prev, newDevice.trim()]);
      setNewDevice("");
    }
  };

  const liveAlerts = useMemo(() => alerts.filter((alert) => !alert.resolved), [alerts]);
  const resolvedAlerts = useMemo(() => alerts.filter((alert) => alert.resolved), [alerts]);

  return (
    <div className="space-y-5 animate-slide-up">
      <h1 className="text-xl font-bold flex items-center gap-2">
        <Settings className="w-5 h-5 text-primary" /> Admin Control Panel
      </h1>

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
              <Button size="sm" variant="outline" onClick={() => void generateLiveSimulation(6).then(refreshAlerts)}>
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
          <div className="space-y-2 mb-3">
            {trustedDevices.map((device, index) => (
              <div key={`${device}-${index}`} className="flex items-center justify-between p-2 rounded-lg bg-secondary/30 text-sm">
                <span>{device}</span>
                <button
                  onClick={() => setTrustedDevices((prev) => prev.filter((_, currentIndex) => currentIndex !== index))}
                  className="text-muted-foreground hover:text-destructive transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <Input
              placeholder="Add device..."
              className="bg-secondary/50 border-border/50 text-sm"
              value={newDevice}
              onChange={(e) => setNewDevice(e.target.value)}
            />
            <Button size="sm" onClick={addDevice}>Add</Button>
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
                    {alert.username} • {new Date(alert.time).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
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
