import { useEffect, useMemo, useState } from "react";
import { Filter, RefreshCw, Search } from "lucide-react";
import {
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import GlassCard from "@/components/GlassCard";
import LoginMap from "@/components/LoginMap";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "@/components/ui/sonner";
import { fetchDashboard, generateLiveSimulation, type DashboardResponse } from "@/lib/api";

const emptyDashboard: DashboardResponse = {
  logs: [],
  timeline: [],
  distribution: [],
};

function formatMfaMethod(method?: string | null) {
  if (method === "email_otp") return "Email OTP";
  if (method === "sms_otp") return "SMS OTP";
  return "None";
}

export default function DashboardPage() {
  const [dashboard, setDashboard] = useState<DashboardResponse>(emptyDashboard);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [loading, setLoading] = useState(false);

  const loadDashboard = async () => {
    setLoading(true);
    try {
      const response = await fetchDashboard();
      if (response.logs.length === 0) {
        await generateLiveSimulation(12);
        const seededResponse = await fetchDashboard();
        setDashboard(seededResponse);
        return;
      }
      setDashboard(response);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to load dashboard data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadDashboard();
    const intervalId = window.setInterval(() => {
      void generateLiveSimulation(2)
        .then(() => loadDashboard())
        .catch((error: unknown) => {
          toast.error(error instanceof Error ? error.message : "Unable to refresh simulated traffic.");
        });
    }, 12000);
    return () => window.clearInterval(intervalId);
  }, []);

  const filtered = useMemo(() => {
    return dashboard.logs.filter((log) => {
      if (search && !log.user.toLowerCase().includes(search.toLowerCase())) return false;
      if (riskFilter === "high" && log.risk < 70) return false;
      if (riskFilter === "medium" && (log.risk < 40 || log.risk >= 70)) return false;
      if (riskFilter === "low" && log.risk >= 40) return false;
      return true;
    });
  }, [dashboard.logs, riskFilter, search]);

  const pieData = dashboard.distribution.length
    ? dashboard.distribution
    : [
        { name: "Normal", value: 0 },
        { name: "Suspicious", value: 0 },
        { name: "Blocked", value: 0 },
      ];
  const pieColors = ["hsl(142,76%,45%)", "hsl(38,92%,55%)", "hsl(0,72%,55%)"];

  return (
    <div className="space-y-5 animate-slide-up">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Security Dashboard</h1>
        <Button variant="outline" size="sm" onClick={() => void loadDashboard()} disabled={loading}>
          <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`} /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <GlassCard className="lg:col-span-2">
          <h3 className="text-sm font-semibold mb-3">Risk Score Over Time</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={dashboard.timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222,30%,18%)" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <YAxis tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(222,47%,9%)",
                  border: "1px solid hsl(222,30%,18%)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Line type="monotone" dataKey="risk" stroke="hsl(187,100%,50%)" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="baseline" stroke="hsl(0,72%,55%)" strokeWidth={1} strokeDasharray="5 5" dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-3">Login Distribution</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value">
                {pieData.map((_, i) => (
                  <Cell key={i} fill={pieColors[i]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(222,47%,9%)",
                  border: "1px solid hsl(222,30%,18%)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center gap-4 text-xs">
            {pieData.map((item, i) => (
              <div key={item.name} className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: pieColors[i] }} />
                <span className="text-muted-foreground">{item.name}</span>
              </div>
            ))}
          </div>
        </GlassCard>
      </div>

      <GlassCard>
        <h3 className="text-sm font-semibold mb-3">Login Geo Map</h3>
        <div className="rounded-xl overflow-hidden border border-border/30">
          <LoginMap logs={dashboard.logs} />
        </div>
      </GlassCard>

      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Filter by username..."
            className="pl-10 bg-secondary/50 border-border/50"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-2">
          {["all", "low", "medium", "high"].map((filterValue) => (
            <Button
              key={filterValue}
              size="sm"
              variant={riskFilter === filterValue ? "default" : "outline"}
              onClick={() => setRiskFilter(filterValue)}
              className="capitalize text-xs"
            >
              {filterValue === "all" && <Filter className="w-3 h-3 mr-1" />}
              {filterValue}
            </Button>
          ))}
        </div>
      </div>

      <GlassCard className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/50 text-muted-foreground text-xs">
              <th className="text-left py-2 px-3 font-medium">User</th>
              <th className="text-left py-2 px-3 font-medium">Time</th>
              <th className="text-left py-2 px-3 font-medium hidden sm:table-cell">Location</th>
              <th className="text-left py-2 px-3 font-medium hidden md:table-cell">Device</th>
              <th className="text-left py-2 px-3 font-medium hidden lg:table-cell">IP</th>
              <th className="text-left py-2 px-3 font-medium hidden lg:table-cell">MFA</th>
              <th className="text-left py-2 px-3 font-medium">Risk</th>
              <th className="text-left py-2 px-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 20).map((log) => (
              <tr
                key={log.id}
                className={`border-b border-border/20 transition-colors hover:bg-secondary/30 ${
                  log.status === "blocked" ? "bg-destructive/5" : ""
                }`}
              >
                <td className="py-2.5 px-3 font-mono text-xs">{log.user}</td>
                <td className="py-2.5 px-3 text-xs text-muted-foreground">
                  {new Date(log.time).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
                </td>
                <td className="py-2.5 px-3 text-xs hidden sm:table-cell">{log.location}</td>
                <td className="py-2.5 px-3 text-xs hidden md:table-cell text-muted-foreground">{log.device}</td>
                <td className="py-2.5 px-3 text-xs hidden lg:table-cell font-mono text-muted-foreground">{log.ip_address}</td>
                <td className="py-2.5 px-3 text-xs hidden lg:table-cell text-muted-foreground">
                  {formatMfaMethod(log.mfa_method)}
                  {log.mfa_verified_at && <span className="ml-1 text-success">verified</span>}
                </td>
                <td className="py-2.5 px-3">
                  <div className="flex items-center gap-2">
                    <div className="w-12 h-1.5 rounded-full bg-secondary overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          log.risk >= 70 ? "bg-destructive" : log.risk >= 40 ? "bg-warning" : "bg-success"
                        }`}
                        style={{ width: `${log.risk}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono">{Math.round(log.risk)}%</span>
                  </div>
                </td>
                <td className="py-2.5 px-3">
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                      log.status === "safe"
                        ? "bg-success/10 text-success"
                        : log.status === "suspicious"
                          ? "bg-warning/10 text-warning"
                          : "bg-destructive/10 text-destructive"
                    }`}
                  >
                    {log.status}
                  </span>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={8} className="py-6 text-center text-sm text-muted-foreground">
                  No login attempts match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </GlassCard>
    </div>
  );
}
