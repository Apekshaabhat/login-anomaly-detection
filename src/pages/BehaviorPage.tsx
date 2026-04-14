import { useState } from "react";
import { Clock, MapPin, Monitor, TrendingUp, BookOpen } from "lucide-react";
import GlassCard from "@/components/GlassCard";
import { generateUserProfile, type UserProfile } from "@/lib/mockData";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
} from "recharts";

export default function BehaviorPage() {
  const [username, setUsername] = useState("alex.chen");
  const [profile, setProfile] = useState<UserProfile>(generateUserProfile("alex.chen"));

  const loadUser = () => {
    if (username.trim()) setProfile(generateUserProfile(username));
  };

  const radarData = [
    { axis: "Login Time", normal: 85, current: 65 + Math.floor(Math.random() * 30) },
    { axis: "Location", normal: 90, current: 40 + Math.floor(Math.random() * 50) },
    { axis: "Device", normal: 95, current: 70 + Math.floor(Math.random() * 25) },
    { axis: "Session Length", normal: 80, current: 50 + Math.floor(Math.random() * 40) },
    { axis: "Action Pattern", normal: 88, current: 55 + Math.floor(Math.random() * 35) },
  ];

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
          <Button size="sm" onClick={loadUser}>Analyze</Button>
        </div>
      </div>

      {/* Cold start badge */}
      {profile.isNewUser && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-warning/10 border border-warning/20 text-warning text-sm animate-fade-in">
          <BookOpen className="w-4 h-4" />
          <span className="font-medium">Learning Mode</span>
          <span className="text-muted-foreground">— Insufficient behavioral data. Model is calibrating.</span>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <GlassCard className="glass-card-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Clock className="w-5 h-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Typical Login Time</p>
              <p className="text-sm font-semibold">{profile.typicalLoginTime}</p>
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
              <p className="text-sm font-semibold">{profile.frequentLocations.join(", ")}</p>
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
              <p className="text-sm font-semibold">{profile.devicesUsed.length} registered</p>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* Comparison panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <GlassCard>
          <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-primary" />
            Current vs Normal Pattern
          </h3>
          <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={radarData}>
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

        {/* Trust Score Timeline */}
        <GlassCard>
          <h3 className="text-sm font-semibold mb-3">Trust Score Timeline</h3>
          <div className="flex items-center gap-2 mb-3">
            <span className="text-3xl font-bold gradient-text">{profile.trustScore}</span>
            <span className="text-xs text-muted-foreground">/ 100</span>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={profile.trustHistory}>
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

      {/* Device list */}
      <GlassCard>
        <h3 className="text-sm font-semibold mb-3">Registered Devices</h3>
        <div className="space-y-2">
          {profile.devicesUsed.map((d, i) => (
            <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-secondary/30 border border-border/30">
              <Monitor className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm">{d}</span>
              <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-success/10 text-success">Trusted</span>
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}
