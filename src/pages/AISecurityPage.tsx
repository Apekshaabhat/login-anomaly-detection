import { useQuery } from "@tanstack/react-query";
import { Activity, AlertTriangle, Brain, CheckCircle2, Fingerprint, Globe2, Radar, ShieldCheck } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import GlassCard from "@/components/GlassCard";
import { fetchAIIntegrations, fetchAISecurityDashboard } from "@/lib/api";

const COLORS = ["hsl(142,76%,45%)", "hsl(38,92%,55%)", "hsl(0,72%,55%)", "hsl(187,100%,50%)"];

export default function AISecurityPage() {
  const dashboardQuery = useQuery({
    queryKey: ["ai-security-dashboard"],
    queryFn: fetchAISecurityDashboard,
    refetchInterval: 10000,
  });
  const integrationsQuery = useQuery({
    queryKey: ["ai-security-integrations"],
    queryFn: fetchAIIntegrations,
    refetchInterval: 30000,
  });
  const data = dashboardQuery.data;
  const integrations = integrationsQuery.data ?? data?.enterprise_capabilities;

  const attackData = data
    ? [
        { name: "Allowed", value: Math.max(0, data.attack_monitoring.total_attempts - data.attack_monitoring.high_risk) },
        { name: "High Risk", value: data.attack_monitoring.high_risk },
        { name: "Blocked", value: data.attack_monitoring.blocked },
        { name: "MFA", value: data.attack_monitoring.mfa_triggered },
      ]
    : [];

  return (
    <div className="space-y-5 animate-slide-up">
      <div>
        <h1 className="text-xl font-bold flex items-center gap-2">
          <Brain className="w-5 h-5 text-primary" /> AI Identity Security
        </h1>
        <p className="text-sm text-muted-foreground">Adaptive risk, continuous authentication, behavioral biometrics, and threat intelligence.</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <GlassCard>
          <p className="text-xs text-muted-foreground flex items-center gap-1.5"><Radar className="w-3.5 h-3.5" /> Avg Risk</p>
          <p className="text-2xl font-bold font-mono">{data?.risk_analytics.average_risk ?? 0}%</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> Session Trust</p>
          <p className="text-2xl font-bold font-mono text-success">{data?.risk_analytics.average_session_trust ?? 100}%</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground flex items-center gap-1.5"><Fingerprint className="w-3.5 h-3.5" /> Bio Events</p>
          <p className="text-2xl font-bold font-mono">{data?.behavioral_biometrics.events ?? 0}</p>
        </GlassCard>
        <GlassCard>
          <p className="text-xs text-muted-foreground flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" /> Fraud Prob.</p>
          <p className="text-2xl font-bold font-mono text-warning">{Math.round((data?.risk_analytics.fraud_probability ?? 0) * 100)}%</p>
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <GlassCard className="xl:col-span-2">
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Activity className="w-4 h-4" /> Anomaly Timeline</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={data?.anomaly_timeline ?? []}>
              <defs>
                <linearGradient id="riskArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(187,100%,50%)" stopOpacity={0.45} />
                  <stop offset="95%" stopColor="hsl(187,100%,50%)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222,30%,18%)" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <YAxis tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <Tooltip contentStyle={{ backgroundColor: "hsl(222,47%,9%)", border: "1px solid hsl(222,30%,18%)", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="risk" stroke="hsl(187,100%,50%)" fill="url(#riskArea)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-3">Attack Mix</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={attackData} cx="50%" cy="50%" innerRadius={52} outerRadius={82} paddingAngle={3} dataKey="value">
                {attackData.map((_, index) => <Cell key={index} fill={COLORS[index % COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: "hsl(222,47%,9%)", border: "1px solid hsl(222,30%,18%)", borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <GlassCard>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Globe2 className="w-4 h-4" /> Login Heatmap</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={data?.login_heatmap ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222,30%,18%)" />
              <XAxis dataKey="country" tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <YAxis tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <Tooltip contentStyle={{ backgroundColor: "hsl(222,47%,9%)", border: "1px solid hsl(222,30%,18%)", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="attempts" fill="hsl(38,92%,55%)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-3">Trust Score Trends</h3>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={data?.trust_score_trends ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222,30%,18%)" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <YAxis tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <Tooltip contentStyle={{ backgroundColor: "hsl(222,47%,9%)", border: "1px solid hsl(222,30%,18%)", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="trust" stroke="hsl(142,76%,45%)" fill="hsl(142,76%,45%)" fillOpacity={0.15} strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-3">Suspicious Sessions</h3>
          <div className="space-y-2 max-h-[260px] overflow-y-auto">
            {(data?.suspicious_sessions ?? []).map((session) => (
              <div key={`${session.session_id}-${session.time}`} className="p-2.5 rounded-lg bg-secondary/30">
                <div className="flex items-center justify-between gap-2">
                  <p className="font-mono text-xs truncate">{session.session_id}</p>
                  <span className={`text-xs px-2 py-0.5 rounded-full ${session.risk_score >= 70 ? "bg-destructive/10 text-destructive" : "bg-warning/10 text-warning"}`}>
                    {session.risk_score}%
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">{session.decision} - trust {session.trust_score}%</p>
              </div>
            ))}
            {(data?.suspicious_sessions ?? []).length === 0 && (
              <p className="text-sm text-muted-foreground text-center py-6">No suspicious live sessions.</p>
            )}
          </div>
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
        {[
          ["Threat Intel", integrations?.threat_intelligence ?? []],
          ["Auth & MFA", integrations?.authentication_mfa ?? []],
          ["Notifications", integrations?.notifications ?? []],
          ["Device Intelligence", integrations?.device_behavior ?? []],
        ].map(([title, items]) => (
          <GlassCard key={title as string}>
            <h3 className="text-sm font-semibold mb-3">{title as string}</h3>
            <div className="space-y-2">
              {(items as Array<{ name: string; configured: boolean; capability: string }>).map((item) => (
                <div key={item.name} className="flex items-start gap-2">
                  <CheckCircle2 className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${item.configured ? "text-success" : "text-muted-foreground"}`} />
                  <div className="min-w-0">
                    <p className="text-xs font-medium truncate">{item.name}</p>
                    <p className="text-[11px] text-muted-foreground leading-snug">{item.capability}</p>
                  </div>
                </div>
              ))}
            </div>
          </GlassCard>
        ))}
      </div>

      <GlassCard>
        <h3 className="text-sm font-semibold mb-3">AI Security Assistant</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
          <div className="p-3 rounded-md bg-secondary/30">
            <p className="font-medium">Risk Explanation</p>
            <p className="text-xs text-muted-foreground mt-1">Explains blocked logins from device trust, IP reputation, behavior drift, and geo-velocity.</p>
          </div>
          <div className="p-3 rounded-md bg-secondary/30">
            <p className="font-medium">Research-Grade Signals</p>
            <p className="text-xs text-muted-foreground mt-1">{data?.ml_strategy?.signals.join(", ") ?? "Collecting behavioral and threat signals."}</p>
          </div>
          <div className="p-3 rounded-md bg-secondary/30">
            <p className="font-medium">ML Upgrade Path</p>
            <p className="text-xs text-muted-foreground mt-1">{data?.ml_strategy?.upgrade_ready.join(", ") ?? "Autoencoder, XGBoost, sequence model."}</p>
          </div>
        </div>
      </GlassCard>
    </div>
  );
}
