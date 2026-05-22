import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Laptop, Lock, ShieldOff, Smartphone, Trash2 } from "lucide-react";
import { Link } from "react-router-dom";

import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/sonner";
import { useAuthStore } from "@/lib/auth-store";
import { fetchUserDevices, revokeUserDevice, trustUserDevice, type DeviceRecord } from "@/lib/api";

function deviceIcon(device: DeviceRecord) {
  return device.device_type === "mobile" ? Smartphone : Laptop;
}

function stateClass(state?: string) {
  if (state === "trusted") return "bg-success/10 text-success";
  if (state === "blocked") return "bg-destructive/10 text-destructive";
  if (state === "suspicious") return "bg-warning/10 text-warning";
  return "bg-secondary text-muted-foreground";
}

export default function DevicesPage() {
  const queryClient = useQueryClient();
  const { isAuthenticated } = useAuthStore();
  const devicesQuery = useQuery({
    queryKey: ["user-devices"],
    queryFn: fetchUserDevices,
    enabled: isAuthenticated,
  });

  const trustMutation = useMutation({
    mutationFn: ({ id, nickname }: { id: number; nickname?: string }) => trustUserDevice(id, nickname),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["user-devices"] });
      toast.success("Device trusted.");
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : "Unable to trust device."),
  });

  const revokeMutation = useMutation({
    mutationFn: revokeUserDevice,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["user-devices"] });
      toast.success("Device revoked.");
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : "Unable to revoke device."),
  });

  const devices = devicesQuery.data ?? [];

  if (!isAuthenticated) {
    return (
      <div className="space-y-5 animate-slide-up">
        <div>
          <h1 className="text-xl font-bold">Trusted Devices</h1>
          <p className="text-sm text-muted-foreground">Sign in to review remembered devices and revoke anything you no longer recognize.</p>
        </div>
        <GlassCard className="max-w-xl">
          <div className="flex items-start gap-3">
            <Lock className="w-5 h-5 text-primary mt-0.5" />
            <div className="space-y-3">
              <div>
                <p className="font-medium">Authentication required</p>
                <p className="text-sm text-muted-foreground">Device management is tied to your current login session.</p>
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
        <h1 className="text-xl font-bold">Trusted Devices</h1>
        <p className="text-sm text-muted-foreground">Review remembered devices and revoke anything you no longer recognize.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {["trusted", "pending_verification", "blocked"].map((state) => (
          <GlassCard key={state}>
            <p className="text-xs text-muted-foreground capitalize">{state.replace("_", " ")}</p>
            <p className="text-2xl font-bold font-mono">{devices.filter((device) => (device.state ?? "pending_verification") === state).length}</p>
          </GlassCard>
        ))}
      </div>

      <GlassCard className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/50 text-xs text-muted-foreground">
              <th className="text-left py-2 px-3 font-medium">Device</th>
              <th className="text-left py-2 px-3 font-medium hidden md:table-cell">Fingerprint</th>
              <th className="text-left py-2 px-3 font-medium hidden lg:table-cell">IP</th>
              <th className="text-left py-2 px-3 font-medium">State</th>
              <th className="text-right py-2 px-3 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((device) => {
              const Icon = deviceIcon(device);
              return (
                <tr key={device.id} className="border-b border-border/20 hover:bg-secondary/30 transition-colors">
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <Icon className="w-4 h-4 text-primary shrink-0" />
                      <div className="min-w-0">
                        <p className="font-medium truncate">{device.nickname || `${device.browser ?? "Browser"} on ${device.os ?? "device"}`}</p>
                        <p className="text-xs text-muted-foreground truncate">{device.screen_resolution ?? "unknown screen"} - {device.timezone ?? "unknown timezone"}</p>
                      </div>
                    </div>
                  </td>
                  <td className="py-3 px-3 hidden md:table-cell font-mono text-xs text-muted-foreground max-w-[240px] truncate">
                    {device.fingerprint}
                  </td>
                  <td className="py-3 px-3 hidden lg:table-cell font-mono text-xs text-muted-foreground">
                    {device.last_ip_address ?? "unknown"}
                  </td>
                  <td className="py-3 px-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${stateClass(device.state)}`}>
                      {(device.state ?? "pending_verification").replace("_", " ")}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex justify-end gap-2">
                      {device.state !== "trusted" && device.state !== "blocked" && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            const nickname = window.prompt("Device nickname", device.nickname ?? "");
                            trustMutation.mutate({ id: device.id, nickname: nickname ?? undefined });
                          }}
                        >
                          <Check className="w-3.5 h-3.5" />
                        </Button>
                      )}
                      <Button size="sm" variant="outline" onClick={() => revokeMutation.mutate(device.id)}>
                        {device.state === "blocked" ? <ShieldOff className="w-3.5 h-3.5" /> : <Trash2 className="w-3.5 h-3.5" />}
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {!devicesQuery.isLoading && devices.length === 0 && (
              <tr>
                <td colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
                  No devices have been recorded for this account yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </GlassCard>
    </div>
  );
}
