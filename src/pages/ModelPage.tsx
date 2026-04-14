import { useState } from "react";
import { Activity, Database, Clock, Target, RefreshCw, AlertTriangle, CheckCircle } from "lucide-react";
import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import { generateModelInfo } from "@/lib/mockData";

export default function ModelPage() {
  const [model, setModel] = useState(generateModelInfo());
  const [retraining, setRetraining] = useState(false);
  const [progress, setProgress] = useState(0);

  const handleRetrain = () => {
    setRetraining(true);
    setProgress(0);
    const iv = setInterval(() => {
      setProgress((p) => {
        if (p >= 100) {
          clearInterval(iv);
          setRetraining(false);
          setModel({
            ...generateModelInfo(),
            lastTrained: new Date().toISOString(),
            accuracy: 96 + Math.random() * 3,
            driftDetected: false,
            driftScore: 0.02,
          });
          return 100;
        }
        return p + 2;
      });
    }, 80);
  };

  return (
    <div className="space-y-5 animate-slide-up">
      <h1 className="text-xl font-bold flex items-center gap-2">
        <Activity className="w-5 h-5 text-primary" /> Model Status
      </h1>

      {/* Drift Warning */}
      {model.driftDetected && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-warning/10 border border-warning/20 text-warning animate-fade-in">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <div>
            <p className="text-sm font-semibold">Behavior Deviation Detected</p>
            <p className="text-xs text-muted-foreground">
              Drift score: {(model.driftScore * 100).toFixed(1)}% — Model retraining recommended
            </p>
          </div>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <GlassCard className="glass-card-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Clock className="w-5 h-5 text-primary" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Last Trained</p>
              <p className="text-sm font-semibold">
                {new Date(model.lastTrained).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}
              </p>
            </div>
          </div>
        </GlassCard>
        <GlassCard className="glass-card-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-success/10">
              <Target className="w-5 h-5 text-success" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Accuracy</p>
              <p className="text-sm font-semibold">{model.accuracy.toFixed(1)}%</p>
            </div>
          </div>
        </GlassCard>
        <GlassCard className="glass-card-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-accent/10">
              <Database className="w-5 h-5 text-accent" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Training Data</p>
              <p className="text-sm font-semibold">{(model.dataSize / 1000).toFixed(0)}K records</p>
            </div>
          </div>
        </GlassCard>
        <GlassCard className="glass-card-hover">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-secondary">
              <Activity className="w-5 h-5 text-foreground" />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Version</p>
              <p className="text-sm font-semibold font-mono">v{model.version}</p>
            </div>
          </div>
        </GlassCard>
      </div>

      {/* Retrain */}
      <GlassCard glow>
        <h3 className="text-sm font-semibold mb-4">Model Retraining</h3>
        {retraining ? (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
              <span className="text-sm">Retraining in progress...</span>
              <span className="ml-auto font-mono text-sm text-primary">{progress}%</span>
            </div>
            <div className="h-2 rounded-full bg-secondary overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-primary to-accent transition-all duration-200"
                style={{ width: `${progress}%` }}
              />
            </div>
            <div className="grid grid-cols-3 gap-3 text-xs text-muted-foreground">
              <div className={progress > 10 ? "text-success" : ""}>
                {progress > 10 ? <CheckCircle className="w-3 h-3 inline mr-1" /> : null}
                Data preprocessing
              </div>
              <div className={progress > 50 ? "text-success" : ""}>
                {progress > 50 ? <CheckCircle className="w-3 h-3 inline mr-1" /> : null}
                Feature extraction
              </div>
              <div className={progress > 85 ? "text-success" : ""}>
                {progress > 85 ? <CheckCircle className="w-3 h-3 inline mr-1" /> : null}
                Model validation
              </div>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-4">
            <Button onClick={handleRetrain}>
              <RefreshCw className="w-4 h-4 mr-2" /> Retrain Model
            </Button>
            <span className="text-xs text-muted-foreground">
              Estimated time: ~45 seconds
            </span>
          </div>
        )}
      </GlassCard>

      {/* Model Architecture */}
      <GlassCard>
        <h3 className="text-sm font-semibold mb-3">Model Architecture</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          {[
            ["Algorithm", "Isolation Forest + LSTM Ensemble"],
            ["Input Features", "12 behavioral signals"],
            ["Update Frequency", "Continuous learning (hourly)"],
            ["False Positive Rate", "< 2.1%"],
            ["Detection Latency", "< 150ms"],
            ["Bias Mitigation", "Fairness-aware sampling"],
          ].map(([label, value]) => (
            <div key={label} className="flex justify-between p-3 rounded-lg bg-secondary/30 border border-border/30">
              <span className="text-muted-foreground">{label}</span>
              <span className="font-medium font-mono text-xs">{value}</span>
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}
