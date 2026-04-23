import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff, KeyRound, Shield, User, Zap } from "lucide-react";

import ExplainableAIPanel from "@/components/ExplainableAIPanel";
import GlassCard from "@/components/GlassCard";
import PasswordStrengthMeter from "@/components/PasswordStrengthMeter";
import RiskGauge from "@/components/RiskGauge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "@/components/ui/sonner";
import { analyzeLogin, loginRequest, verifyOtp } from "@/lib/api";

type LoginState = "idle" | "loading" | "risk-check" | "otp" | "success";

function getDeviceId() {
  const platform = navigator.platform || "web";
  const agent = navigator.userAgent || "browser";
  return `${platform}-${agent}`.replace(/\s+/g, "-").slice(0, 120);
}

export default function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [state, setState] = useState<LoginState>("idle");
  const [risk, setRisk] = useState(0);
  const [level, setLevel] = useState<"LOW" | "MEDIUM" | "HIGH">("LOW");
  const [otp, setOtp] = useState("");
  const [debugOtp, setDebugOtp] = useState<string | null>(null);
  const [reasons, setReasons] = useState<string[]>([]);
  const [verificationToken, setVerificationToken] = useState<string | null>(null);

  const analysisPayload = useMemo(() => {
    const now = new Date();
    return {
      login_hour: Number((now.getHours() + now.getMinutes() / 60).toFixed(2)),
      location_lat: 19.076,
      location_lon: 72.8777,
      typing_speed: Math.max(1, Number((password.length / 2.4).toFixed(2))),
      failed_attempts: username.toLowerCase().includes("attacker") ? 6 : 0,
      device_id: getDeviceId(),
      ip_address: "127.0.0.1",
    };
  }, [password, username]);

  const syncRiskState = (payload: { risk_score: number; level: "LOW" | "MEDIUM" | "HIGH"; reasons: string[] }) => {
    setRisk(Math.round(payload.risk_score));
    setLevel(payload.level);
    setReasons(payload.reasons);
  };

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) {
      toast.error("Enter both username and password to continue.");
      return;
    }

    setState("loading");
    setDebugOtp(null);
    setVerificationToken(null);

    try {
      const result = await loginRequest({
        username: username.trim(),
        password,
        ...analysisPayload,
      });

      syncRiskState(result);

      if (result.decision === "require_verification" && result.verification_token) {
        setVerificationToken(result.verification_token);
        setDebugOtp(result.debug_otp ?? null);
        setState("otp");
        toast.warning("Extra verification is required for this login.");
        return;
      }

      if (result.decision === "block") {
        setState("risk-check");
        toast.error(result.reasons[0] ?? "This login was blocked.");
        return;
      }

      setState("risk-check");
      window.setTimeout(() => setState("success"), 1200);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unable to analyze this login.";
      if (message === "Invalid credentials") {
        try {
          const fallback = await analyzeLogin({
            username: username.trim(),
            ...analysisPayload,
          });
          syncRiskState(fallback);
          setState("risk-check");
          toast.warning("Analyzed risk only. Credentials were not accepted by the backend.");
          return;
        } catch (fallbackError) {
          setState("idle");
          toast.error(fallbackError instanceof Error ? fallbackError.message : "Unable to analyze this login.");
          return;
        }
      }
      setState("idle");
      toast.error(message);
    }
  };

  const handleOtp = async () => {
    if (!verificationToken || otp.length !== 6) {
      toast.error("Enter the full 6-digit OTP.");
      return;
    }

    setState("loading");
    try {
      await verifyOtp(username.trim(), otp, verificationToken);
      setState("success");
      toast.success("OTP verified successfully.");
    } catch (error) {
      setState("otp");
      toast.error(error instanceof Error ? error.message : "OTP verification failed.");
    }
  };

  const handleSimulateAttack = async () => {
    setUsername("attacker_bot");
    setPassword("password123");
    setState("loading");

    try {
      const result = await analyzeLogin({
        username: "attacker_bot",
        ...analysisPayload,
        failed_attempts: 8,
        typing_speed: 12,
        device_id: "unknown-device-attack",
      });
      syncRiskState(result);
      setVerificationToken(result.verification_token ?? null);
      setDebugOtp(result.debug_otp ?? null);
      setState("risk-check");
    } catch (error) {
      setState("idle");
      toast.error(error instanceof Error ? error.message : "Simulation failed.");
    }
  };

  return (
    <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center py-8">
      <div className="w-full max-w-md space-y-5 animate-slide-up">
        <div className="text-center space-y-2">
          <div className="inline-flex p-3 rounded-2xl bg-primary/10 cyber-glow mb-2">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <h1 className="text-2xl font-bold">Secure Login</h1>
          <p className="text-sm text-muted-foreground">AI-powered adaptive authentication</p>
        </div>

        {state === "success" ? (
          <GlassCard glow className="text-center space-y-4 animate-slide-up">
            <div className="w-16 h-16 rounded-full bg-success/10 flex items-center justify-center mx-auto">
              <Shield className="w-8 h-8 text-success" />
            </div>
            <h2 className="text-lg font-semibold text-success">Login Successful</h2>
            <p className="text-sm text-muted-foreground">
              Verified with a {level.toLowerCase()} risk score of {risk}%.
            </p>
            <Button className="w-full" onClick={() => navigate("/dashboard")}>
              Go to Dashboard
            </Button>
          </GlassCard>
        ) : (
          <>
            <GlassCard glow>
              <div className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Username</label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      placeholder="Enter username"
                      className="pl-10 bg-secondary/50 border-border/50"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      disabled={state !== "idle"}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Password</label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      type={showPw ? "text" : "password"}
                      placeholder="Enter password"
                      className="pl-10 pr-10 bg-secondary/50 border-border/50"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={state !== "idle"}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPw(!showPw)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  <PasswordStrengthMeter password={password} />
                </div>

                {state === "idle" && (
                  <Button className="w-full" onClick={handleLogin} disabled={!username.trim() || !password.trim()}>
                    Analyze & Authenticate
                  </Button>
                )}

                {state === "loading" && (
                  <Button className="w-full" disabled>
                    <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
                    Analyzing behavior...
                  </Button>
                )}
              </div>
            </GlassCard>

            {state === "otp" && (
              <GlassCard className="border-warning/30 animate-slide-up space-y-4">
                <div className="flex items-center gap-2 text-warning">
                  <Shield className="w-5 h-5" />
                  <h3 className="font-semibold text-sm">Additional Verification Required</h3>
                </div>
                <p className="text-xs text-muted-foreground">
                  Risk score {risk}% ({level}). Enter the OTP to continue.
                </p>
                {debugOtp && (
                  <p className="text-xs text-muted-foreground">
                    Debug OTP: <span className="font-mono text-foreground">{debugOtp}</span>
                  </p>
                )}
                <div className="flex items-center justify-center">
                  <RiskGauge risk={risk} />
                </div>
                <Input
                  placeholder="Enter 6-digit OTP"
                  className="bg-secondary/50 border-border/50 text-center font-mono text-lg tracking-[0.5em]"
                  maxLength={6}
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))}
                />
                <Button className="w-full" onClick={handleOtp} disabled={otp.length !== 6}>
                  Verify OTP
                </Button>
              </GlassCard>
            )}

            {state === "risk-check" && (
              <GlassCard className="animate-slide-up text-center space-y-3">
                <div className="flex items-center justify-center">
                  <RiskGauge risk={risk} />
                </div>
                <p className={`text-sm font-medium ${level === "HIGH" ? "text-destructive" : "text-success"}`}>
                  {level === "HIGH" ? "High risk detected - access limited." : "Risk check complete."}
                </p>
              </GlassCard>
            )}

            {(state === "otp" || state === "risk-check") && reasons.length > 0 && (
              <ExplainableAIPanel reasons={reasons} risk={risk} />
            )}

            {state === "idle" && (
              <button
                onClick={handleSimulateAttack}
                className="w-full flex items-center justify-center gap-2 text-xs text-muted-foreground hover:text-destructive transition-colors py-2"
              >
                <Zap className="w-3.5 h-3.5" />
                Simulate Suspicious Login
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}
