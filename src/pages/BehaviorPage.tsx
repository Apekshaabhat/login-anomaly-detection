import { useEffect, useState } from "react";
import { BookOpen, Clock, MapPin, Monitor, TrendingUp } from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "@/components/ui/sonner";
import { fetchBehavior, type BehaviorResponse } from "@/lib/api";

const emptyBehavior: BehaviorResponse = {
  username: "alex.chen",
  is_new_user: true,
  typical_login_time: "No data yet",
  frequent_locations: [],
  devices_used: [],
  trust_score: 0,
  trend_data: [],
  comparison_data: [],
  trust_history: [],
  failed_attempts: 0,
};

export default function BehaviorPage() {
  const [username, setUsername] = useState("alex.chen");
  const [profile, setProfile] = useState<BehaviorResponse>(emptyBehavior);
  const [loading, setLoading] = useState(false);

  const loadUser = async (targetUsername: string) => {
    const trimmed = targetUsername.trim();
    if (!trimmed) {
      toast.error("Enter a username to analyze.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetchBehavior(trimmed);
      setProfile(response);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to load user behavior.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadUser(username);
  }, []);

  return (
    <div className="space-y-5 animate-slide-up">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h1 className="text-xl font-bold">User Behavior Analysis</h1>
        <div className="flex gap-2">
          <Input
            placeholder="Username"
            className="w-40 bg-secondary/50 border-border/50 text-sm"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Button size="sm" onClick={() => void loadUser(username)} disabled={loading}>
            {loading ? "Loading..." : "Analyze"}
          </Button>
        </div>
      </div>

      {profile.is_new_user && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-warning/10 border border-warning/20 text-warning text-sm animate-fade-in">
          <BookOpen className="w-4 h-4" />
          <span className="font-medium">Learning Mode</span>
          <span className="text-muted-foreground">- Insufficient behavioral data. Model is calibrating.</span>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <GlassCard className="glass-card-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Clock className="w-5 h-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Typical Login Time</p>
              <p className="text-sm font-semibold">{profile.typical_login_time}</p>
            </div>
          </div>
        </GlassCard>
        <GlassCard className="glass-card-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-success/10">
              <MapPin className="w-5 h-5 text-success" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Frequent Locations</p>
              <p className="text-sm font-semibold">{profile.frequent_locations.join(", ") || "No locations yet"}</p>
            </div>
          </div>
        </GlassCard>
        <GlassCard className="glass-card-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-accent/10">
              <Monitor className="w-5 h-5 text-accent" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Devices Used</p>
              <p className="text-sm font-semibold">{profile.devices_used.length} registered</p>
            </div>
          </div>
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <GlassCard>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-primary" />
            Current vs Normal Pattern
          </h3>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={profile.comparison_data}>
              <PolarGrid stroke="hsl(222,30%,18%)" />
              <PolarAngleAxis dataKey="axis" tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <Radar name="Normal" dataKey="normal" stroke="hsl(142,76%,45%)" fill="hsl(142,76%,45%)" fillOpacity={0.15} />
              <Radar name="Current" dataKey="current" stroke="hsl(187,100%,50%)" fill="hsl(187,100%,50%)" fillOpacity={0.15} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(222,47%,9%)",
                  border: "1px solid hsl(222,30%,18%)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
            </RadarChart>
          </ResponsiveContainer>
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-3">Trust Score Timeline</h3>
          <div className="flex items-center gap-2 mb-3">
            <span className="text-3xl font-bold gradient-text">{Math.round(profile.trust_score)}</span>
            <span className="text-xs text-muted-foreground">/ 100</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={profile.trust_history}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222,30%,18%)" />
              <XAxis dataKey="date" tick={{ fontSize: 9, fill: "hsl(215,20%,55%)" }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(222,47%,9%)",
                  border: "1px solid hsl(222,30%,18%)",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              <Line type="monotone" dataKey="score" stroke="hsl(270,80%,60%)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </GlassCard>
      </div>

      <GlassCard>
        <h3 className="text-sm font-semibold mb-3">Behavior Trends</h3>
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={profile.trend_data}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(222,30%,18%)" />
            <XAxis dataKey="label" tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
            <YAxis tick={{ fontSize: 10, fill: "hsl(215,20%,55%)" }} />
            <Tooltip
              contentStyle={{
                backgroundColor: "hsl(222,47%,9%)",
                border: "1px solid hsl(222,30%,18%)",
                borderRadius: 8,
                fontSize: 12,
              }}
            />
            <Line type="monotone" dataKey="login_count" stroke="hsl(187,100%,50%)" strokeWidth={2} dot={false} name="Login Trends" />
            <Line type="monotone" dataKey="avg_typing_speed" stroke="hsl(142,76%,45%)" strokeWidth={2} dot={false} name="Typing Speed" />
            <Line type="monotone" dataKey="failed_attempts" stroke="hsl(0,72%,55%)" strokeWidth={2} dot={false} name="Failed Attempts" />
          </LineChart>
        </ResponsiveContainer>
      </GlassCard>

      <GlassCard>
        <h3 className="text-sm font-semibold mb-3">Registered Devices</h3>
        <div className="space-y-2">
          {profile.devices_used.length === 0 && (
            <div className="p-3 rounded-lg bg-secondary/30 border border-border/30 text-sm text-muted-foreground">
              No trusted devices recorded yet.
            </div>
          )}
          {profile.devices_used.map((device, index) => (
            <div key={`${device}-${index}`} className="flex items-center gap-3 p-3 rounded-lg bg-secondary/30 border border-border/30">
              <Monitor className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm">{device}</span>
              <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-success/10 text-success">Trusted</span>
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}
