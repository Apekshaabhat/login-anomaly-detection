interface Props {
  password: string;
}

function getStrength(pw: string): { score: number; label: string; color: string } {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  if (score <= 1) return { score: 20, label: "Very Weak", color: "bg-destructive" };
  if (score === 2) return { score: 40, label: "Weak", color: "bg-destructive/70" };
  if (score === 3) return { score: 60, label: "Fair", color: "bg-warning" };
  if (score === 4) return { score: 80, label: "Strong", color: "bg-success/80" };
  return { score: 100, label: "Very Strong", color: "bg-success" };
}

export default function PasswordStrengthMeter({ password }: Props) {
  if (!password) return null;
  const { score, label, color } = getStrength(password);

  return (
    <div className="space-y-1.5 animate-fade-in">
      <div className="flex justify-between text-xs">
        <span className="text-muted-foreground">Password Strength</span>
        <span className="font-medium">{label}</span>
      </div>
      <div className="h-1.5 rounded-full bg-secondary overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ease-out ${color}`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  );
}
