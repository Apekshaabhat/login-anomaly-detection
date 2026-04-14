import { useState, useEffect } from "react";
import { Settings, Bell, Shield, MapPin, Monitor, Check, X } from "lucide-react";
import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { generateAlerts, type Alert } from "@/lib/mockData";

export default function AdminPage() {
  const [threshold, setThreshold] = useState(65);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [trustedDevices, setTrustedDevices] = useState(["Chrome / Windows 11", "Safari / macOS 14"]);
  const [trustedLocations, setTrustedLocations] = useState(["New York, US", "Toronto, CA"]);
  const [newDevice, setNewDevice] = useState("");
  const [newLocation, setNewLocation] = useState("");

  useEffect(() => {
    setAlerts(generateAlerts(15));
  }, []);

  const resolveAlert = (id: string) => {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, resolved: true } : a)));
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

  const addLocation = () => {
    if (newLocation.trim() && !trustedLocations.includes(newLocation.trim())) {
      setTrustedLocations((prev) => [...prev, newLocation.trim()]);
      setNewLocation("");
    }
  };

  const liveAlerts = alerts.filter((a) => !a.resolved);
  const resolvedAlerts = alerts.filter((a) => a.resolved);

  return (
    <div className="space-y-5 animate-slide-up">
      <h1 className="text-xl font-bold flex items-center gap-2">
        <Settings className="w-5 h-5 text-primary" /> Admin Control Panel
      </h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Threshold */}
        <GlassCard glow>
          <h3 className="text-sm font-semibold mb-4">Anomaly Detection Threshold</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Sensitivity</span>
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
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>Lenient (more false negatives)</span>
              <span>Strict (more false positives)</span>
            </div>
          </div>
        </GlassCard>

        {/* Trusted Devices */}
        <GlassCard>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Monitor className="w-4 h-4" /> Trusted Devices
          </h3>
          <div className="space-y-2 mb-3">
            {trustedDevices.map((d, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-secondary/30 text-sm">
                <span>{d}</span>
                <button
                  onClick={() => setTrustedDevices((p) => p.filter((_, j) => j !== i))}
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

        {/* Trusted Locations */}
        <GlassCard>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <MapPin className="w-4 h-4" /> Trusted Locations
          </h3>
          <div className="space-y-2 mb-3">
            {trustedLocations.map((l, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded-lg bg-secondary/30 text-sm">
                <span>{l}</span>
                <button
                  onClick={() => setTrustedLocations((p) => p.filter((_, j) => j !== i))}
                  className="text-muted-foreground hover:text-destructive transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <Input
              placeholder="Add location..."
              className="bg-secondary/50 border-border/50 text-sm"
              value={newLocation}
              onChange={(e) => setNewLocation(e.target.value)}
            />
            <Button size="sm" onClick={addLocation}>Add</Button>
          </div>
        </GlassCard>

        {/* Live Alerts */}
        <GlassCard className="border-destructive/20">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <Bell className="w-4 h-4 text-destructive" /> Live Alerts
            {liveAlerts.length > 0 && (
              <span className="text-xs px-2 py-0.5 rounded-full bg-destructive/10 text-destructive font-mono">
                {liveAlerts.length}
              </span>
            )}
          </h3>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {liveAlerts.length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-4">No active alerts</p>
            )}
            {liveAlerts.map((alert) => (
              <div key={alert.id} className="flex items-start gap-3 p-2.5 rounded-lg bg-secondary/30 animate-fade-in">
                <Shield className="w-4 h-4 text-destructive mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm">{alert.message}</p>
                  <p className="text-xs text-muted-foreground">
                    {new Date(alert.time).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                  </p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full shrink-0 ${severityColor[alert.severity]}`}>
                  {alert.severity}
                </span>
                <button
                  onClick={() => resolveAlert(alert.id)}
                  className="text-muted-foreground hover:text-success transition-colors shrink-0"
                  title="Mark as safe"
                >
                  <Check className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        </GlassCard>
      </div>

      {/* Alert History */}
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
