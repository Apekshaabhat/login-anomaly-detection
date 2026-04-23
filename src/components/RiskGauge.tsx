interface Props {
  risk: number;
  size?: "sm" | "lg";
}

export default function RiskGauge({ risk, size = "lg" }: Props) {
  const r = size === "lg" ? 60 : 32;
  const stroke = size === "lg" ? 8 : 5;
  const circumference = 2 * Math.PI * r;
  const progress = (risk / 100) * circumference * 0.75; // 270 degree arc
  const color =
    risk < 40 ? "text-success" : risk < 70 ? "text-warning" : "text-destructive";
  const label = risk < 40 ? "Low Risk" : risk < 70 ? "Medium Risk" : "High Risk";
  const dim = (r + stroke) * 2;

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={dim} height={dim} className="transform -rotate-[135deg]">
        <circle
          cx={r + stroke}
          cy={r + stroke}
          r={r}
          fill="none"
          stroke="hsl(var(--secondary))"
          strokeWidth={stroke}
          strokeDasharray={`${circumference * 0.75} ${circumference * 0.25}`}
          strokeLinecap="round"
        />
        <circle
          cx={r + stroke}
          cy={r + stroke}
          r={r}
          fill="none"
          stroke="currentColor"
          className={`${color} transition-all duration-1000 ease-out`}
          strokeWidth={stroke}
          strokeDasharray={`${progress} ${circumference - progress}`}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute flex flex-col items-center" style={{ marginTop: size === "lg" ? 30 : 12 }}>
        <span className={`font-mono font-bold ${size === "lg" ? "text-3xl" : "text-lg"} ${color}`}>
          {risk}
        </span>
        {size === "lg" && <span className="text-xs text-muted-foreground mt-0.5">{label}</span>}
      </div>
    </div>
  );
}
