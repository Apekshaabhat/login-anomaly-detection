import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Clock,
  Database,
  RefreshCw,
  Target,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  explainModel,
  fetchModelDrift,
  fetchModelConfusionMatrix,
  fetchModelHistory,
  fetchModelMonitoring,
  fetchModelRegistry,
  fetchModelStatus,
  retrainModel,
  type ModelDriftResponse,
  type ModelExplainResponse,
  type ModelConfusionMatrixResponse,
  type ModelStatusResponse,
} from "@/lib/api";

const sampleLoginFeatures = {
  login_hour: 2,
  location_lat: 40.7128,
  location_lon: -74.006,
  typing_speed: 18,
  failed_attempts: 3,
  ip_risk_score: 0.5,
  device_usage_frequency: 0,
  login_interval_hours: 1,
  geo_distance_from_last_login: 1200,
};

export default function ModelPage() {
  const queryClient = useQueryClient();
  const [progress, setProgress] = useState(0);
  const [selectedVersion, setSelectedVersion] = useState<string>("");

  const statusQuery = useQuery({
    queryKey: ["model-status"],
    queryFn: fetchModelStatus,
    refetchInterval: 15000,
    retry: 1,
  });

  const driftQuery = useQuery({
    queryKey: ["model-drift"],
    queryFn: fetchModelDrift,
    refetchInterval: 20000,
    retry: 1,
  });

  const historyQuery = useQuery({
    queryKey: ["model-history"],
    queryFn: fetchModelHistory,
    retry: 1,
  });

  const monitoringQuery = useQuery({
    queryKey: ["model-monitoring"],
    queryFn: fetchModelMonitoring,
    refetchInterval: 15000,
    retry: 1,
  });

  const confusionMatrixQuery = useQuery({
    queryKey: ["model-confusion-matrix"],
    queryFn: fetchModelConfusionMatrix,
    refetchInterval: 20000,
    retry: 1,
  });

  const registryQuery = useQuery({
    queryKey: ["model-registry"],
    queryFn: fetchModelRegistry,
    retry: 1,
  });

  const explainQuery = useQuery({
    queryKey: ["model-explain", sampleLoginFeatures],
    queryFn: () => explainModel(sampleLoginFeatures),
    retry: 1,
  });

  const retrainMutation = useMutation({
    mutationFn: retrainModel,
    onMutate: () => {
      setProgress(8);
      toast.info("Model retraining started");
    },
    onSuccess: (result) => {
      setProgress(100);
      toast.success(`Retrained model ${result.new_version}`);
      queryClient.invalidateQueries({ queryKey: ["model-status"] });
      queryClient.invalidateQueries({ queryKey: ["model-drift"] });
      queryClient.invalidateQueries({ queryKey: ["model-history"] });
      queryClient.invalidateQueries({ queryKey: ["model-monitoring"] });
    },
    onError: (error) => {
      setProgress(0);
      toast.error(error instanceof Error ? error.message : "Model retraining failed");
    },
  });

  const model = statusQuery.data;
  const drift = driftQuery.data;
  const explain = explainQuery.data;
  const monitoring = monitoringQuery.data;
  const confusionMatrix = confusionMatrixQuery.data ?? model?.confusion_matrix;
  const registry = registryQuery.data;
  const history = historyQuery.data ?? [];
  const currentVersion = selectedVersion || model?.version || history[0]?.version || "v1.0";

  const retraining = retrainMutation.isPending;
  const progressValue = useMemo(() => {
    if (!retraining) return progress;
    return Math.min(95, Math.max(progress, 45));
  }, [progress, retraining]);

  const hasError = statusQuery.isError || driftQuery.isError || monitoringQuery.isError;

  const handleRetrain = () => {
    setProgress(0);
    retrainMutation.mutate();
  };

  const handleRetry = () => {
    statusQuery.refetch();
    driftQuery.refetch();
    monitoringQuery.refetch();
    explainQuery.refetch();
  };

  return (
    <div className="space-y-5 animate-slide-up">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <h1 className="text-xl font-bold flex items-center gap-2">
          <Activity className="w-5 h-5 text-primary" /> Model Status
        </h1>
        <div className="flex items-center gap-2">
          <select
            className="h-9 rounded-md border border-border bg-background px-3 text-sm"
            value={currentVersion}
            onChange={(event) => setSelectedVersion(event.target.value)}
          >
            {[currentVersion, ...history.map((item) => item.version)]
              .filter((item, index, arr) => item && arr.indexOf(item) === index)
              .map((version) => (
                <option key={version} value={version}>
                  {version}
                </option>
              ))}
          </select>
          <Button variant="outline" size="sm" onClick={handleRetry}>
            <RefreshCw className="w-4 h-4 mr-2" /> Retry
          </Button>
        </div>
      </div>

      {hasError && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-destructive/10 border border-destructive/20 text-destructive animate-fade-in">
          <AlertTriangle className="w-5 h-5 shrink-0" />
          <div>
            <p className="text-sm font-semibold">Model APIs are temporarily unavailable</p>
            <p className="text-xs text-muted-foreground">The dashboard is preserved; retry when the backend is ready.</p>
          </div>
        </div>
      )}

      {drift?.drift_detected && <DriftWarning drift={drift} />}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard icon={Clock} label="Last Trained" value={formatDate(model?.last_trained)} loading={statusQuery.isLoading} />
        <MetricCard icon={Target} label="Accuracy" value={formatPercent(model?.accuracy)} loading={statusQuery.isLoading} />
        <MetricCard icon={Database} label="Training Data" value={`${model?.dataset_size ?? 0} records`} loading={statusQuery.isLoading} />
        <MetricCard icon={Activity} label="Health" value={model?.status ?? "unavailable"} loading={statusQuery.isLoading} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <GlassCard className="lg:col-span-2">
          <h3 className="text-sm font-semibold mb-4">Live Model Metrics</h3>
          {statusQuery.isLoading ? (
            <Skeleton className="h-36 w-full" />
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <SmallMetric label="Precision" value={formatPercent(model?.precision)} />
              <SmallMetric label="Recall" value={formatPercent(model?.recall)} />
              <SmallMetric label="F1 Score" value={formatPercent(model?.f1_score)} />
              <SmallMetric label="ROC AUC" value={formatPercent(model?.roc_auc)} />
              <SmallMetric label="False Positives" value={formatPercent(model?.false_positive_rate)} />
              <SmallMetric label="Inference" value={`${model?.inference_time_ms?.toFixed(2) ?? "0.00"} ms`} />
            </div>
          )}
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-4">Monitoring</h3>
          {monitoringQuery.isLoading ? (
            <Skeleton className="h-36 w-full" />
          ) : (
            <div className="space-y-3">
              <SmallMetric label="Predictions Logged" value={`${monitoring?.total_predictions ?? 0}`} />
              <SmallMetric label="Anomaly Rate" value={formatPercent(monitoring?.anomaly_rate)} />
              <SmallMetric label="P95 Latency" value={`${monitoring?.p95_latency_ms?.toFixed(2) ?? "0.00"} ms`} />
            </div>
          )}
        </GlassCard>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <GlassCard>
          <h3 className="text-sm font-semibold mb-4">Confusion Matrix</h3>
          {confusionMatrixQuery.isLoading && !confusionMatrix ? (
            <Skeleton className="h-40 w-full" />
          ) : (
            <ConfusionMatrix matrix={confusionMatrix} />
          )}
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-4">Model Registry</h3>
          <div className="space-y-2">
            {(registry?.models ?? model?.available_models ?? []).map((item) => (
              <div key={item.key} className="flex items-center justify-between rounded-lg border border-border/30 bg-secondary/30 p-3">
                <div>
                  <p className="text-sm font-medium">{item.name}</p>
                  <p className="text-xs text-muted-foreground font-mono">{item.key}</p>
                </div>
                <span className={item.available ? "text-xs text-success" : "text-xs text-muted-foreground"}>
                  {item.available ? "active-ready" : "registered"}
                </span>
              </div>
            ))}
          </div>
        </GlassCard>
      </div>

      <GlassCard glow>
        <h3 className="text-sm font-semibold mb-4">Model Retraining</h3>
        {retraining ? (
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
              <span className="text-sm">Retraining in progress...</span>
              <span className="ml-auto font-mono text-sm text-primary">{progressValue}%</span>
            </div>
            <div className="h-2 rounded-full bg-secondary overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-primary to-accent transition-all duration-200"
                style={{ width: `${progressValue}%` }}
              />
            </div>
            <div className="grid grid-cols-3 gap-3 text-xs text-muted-foreground">
              <StepLabel done={progressValue > 10} label="Data validation" />
              <StepLabel done={progressValue > 45} label="Isolation Forest fit" />
              <StepLabel done={progressValue > 80} label="Artifact save" />
            </div>
          </div>
        ) : (
          <div className="flex flex-col sm:flex-row sm:items-center gap-4">
            <Button onClick={handleRetrain}>
              <RefreshCw className="w-4 h-4 mr-2" /> Retrain Model
            </Button>
            <span className="text-xs text-muted-foreground">
              Uses successful login attempts and swaps the trained model in memory after validation.
            </span>
          </div>
        )}
      </GlassCard>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <GlassCard>
          <h3 className="text-sm font-semibold mb-4">Drift Trend</h3>
          <FeatureBars
            items={(drift?.affected_features ?? []).map((item) => ({
              label: item.feature.replaceAll("_", " "),
              value: item.score,
            }))}
            emptyLabel="No feature drift above threshold."
          />
        </GlassCard>

        <GlassCard>
          <h3 className="text-sm font-semibold mb-4">Feature Importance</h3>
          <FeatureBars
            items={(explain?.top_factors ?? []).map((item) => ({
              label: item.feature.replaceAll("_", " "),
              value: item.impact,
            }))}
            emptyLabel="No explanation data available yet."
          />
          {explain?.explanation && (
            <p className="mt-4 text-xs text-muted-foreground">{explain.explanation}</p>
          )}
        </GlassCard>
      </div>

      <GlassCard>
        <h3 className="text-sm font-semibold mb-3">Model Architecture</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
          {[
            ["Algorithm", model?.model_name ?? "Isolation Forest"],
            ["Input Features", "9 behavioral signals"],
            ["Update Frequency", "Manual + automatic backend retraining"],
            ["Drift Method", "PSI + KL divergence"],
            ["Detection Latency", `${model?.inference_time_ms?.toFixed(2) ?? "0.00"} ms`],
            ["Version", currentVersion],
          ].map(([label, value]) => (
            <div key={label} className="flex justify-between p-3 rounded-lg bg-secondary/30 border border-border/30">
              <span className="text-muted-foreground">{label}</span>
              <span className="font-medium font-mono text-xs text-right">{value}</span>
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}

function DriftWarning({ drift }: { drift: ModelDriftResponse }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-warning/10 border border-warning/20 text-warning animate-fade-in">
      <AlertTriangle className="w-5 h-5 shrink-0" />
      <div>
        <p className="text-sm font-semibold">Behavior Deviation Detected</p>
        <p className="text-xs text-muted-foreground">
          Drift score: {drift.drift_score.toFixed(3)}. Model retraining is recommended.
        </p>
      </div>
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  loading,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  loading: boolean;
}) {
  return (
    <GlassCard className="glass-card-hover">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-primary/10">
          <Icon className="w-5 h-5 text-primary" />
        </div>
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground">{label}</p>
          {loading ? <Skeleton className="h-4 w-24 mt-1" /> : <p className="text-sm font-semibold truncate">{value}</p>}
        </div>
      </div>
    </GlassCard>
  );
}

function SmallMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-3 rounded-lg bg-secondary/30 border border-border/30">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-sm font-semibold font-mono">{value}</p>
    </div>
  );
}

function FeatureBars({ items, emptyLabel }: { items: Array<{ label: string; value: number }>; emptyLabel: string }) {
  if (!items.length) {
    return <p className="text-sm text-muted-foreground">{emptyLabel}</p>;
  }
  return (
    <div className="space-y-3">
      {items.slice(0, 6).map((item) => (
        <div key={item.label} className="space-y-1">
          <div className="flex items-center justify-between gap-3 text-xs">
            <span className="capitalize text-muted-foreground">{item.label}</span>
            <span className="font-mono">{(item.value * 100).toFixed(1)}%</span>
          </div>
          <div className="h-2 rounded-full bg-secondary overflow-hidden">
            <div className="h-full rounded-full bg-primary" style={{ width: `${Math.min(100, item.value * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function ConfusionMatrix({ matrix }: { matrix?: ModelConfusionMatrixResponse }) {
  if (!matrix) {
    return <p className="text-sm text-muted-foreground">No confusion matrix data available yet.</p>;
  }
  const [[tn = 0, fp = 0] = [], [fn = 0, tp = 0] = []] = matrix.matrix;
  const cells = [
    { label: "True Normal", value: tn, tone: "bg-success/15 text-success" },
    { label: "False Alert", value: fp, tone: "bg-warning/15 text-warning" },
    { label: "Missed Anomaly", value: fn, tone: "bg-destructive/15 text-destructive" },
    { label: "True Anomaly", value: tp, tone: "bg-primary/15 text-primary" },
  ];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        {cells.map((cell) => (
          <div key={cell.label} className={`rounded-lg p-4 ${cell.tone}`}>
            <p className="text-xs">{cell.label}</p>
            <p className="text-2xl font-bold font-mono">{cell.value}</p>
          </div>
        ))}
      </div>
      <p className="text-xs text-muted-foreground">
        Rows are actual labels and columns are predicted labels. Total evaluated attempts: {matrix.total}.
      </p>
    </div>
  );
}

function StepLabel({ done, label }: { done: boolean; label: string }) {
  return (
    <div className={done ? "text-success" : ""}>
      {done ? <CheckCircle className="w-3 h-3 inline mr-1" /> : <Zap className="w-3 h-3 inline mr-1" />}
      {label}
    </div>
  );
}

function formatPercent(value?: number) {
  return `${((value ?? 0) * 100).toFixed(1)}%`;
}

function formatDate(value?: string) {
  if (!value) return "Not trained";
  return new Date(value).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
