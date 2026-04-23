import { AlertTriangle, Clock, Fingerprint, MapPin, Monitor } from "lucide-react";

import GlassCard from "./GlassCard";

interface Props {
  reasons: string[];
  risk: number;
}

const iconMap: Record<string, React.ElementType> = {
  "New device detected": Monitor,
  "Unusual location": MapPin,
  "Login outside normal hours": Clock,
  "Multiple failed attempts": AlertTriangle,
  "Behavioral anomaly": Fingerprint,
  "High travel speed detected": MapPin,
};

export default function ExplainableAIPanel({ reasons, risk }: Props) {
  if (reasons.length === 0) return null;

  return (
    <GlassCard className="animate-slide-up border-destructive/30">
      <h3 className="text-sm font-semibold text-destructive flex items-center gap-2 mb-3">
        <AlertTriangle className="w-4 h-4" />
        AI Explanation - Why This Login Was Flagged
      </h3>
      <div className="space-y-2">
        {reasons.map((reason, i) => {
          const Icon = iconMap[reason] || AlertTriangle;
          return (
            <div
              key={`${reason}-${i}`}
              className="flex items-center gap-3 p-2.5 rounded-lg bg-destructive/5 border border-destructive/10 text-sm animate-fade-in"
              style={{ animationDelay: `${i * 100}ms` }}
            >
              <Icon className="w-4 h-4 text-destructive shrink-0" />
              <span>{reason}</span>
              <span className="ml-auto text-xs text-muted-foreground font-mono">
                +{Math.max(1, Math.floor(risk / reasons.length))}%
              </span>
            </div>
          );
        })}
      </div>
    </GlassCard>
  );
}
