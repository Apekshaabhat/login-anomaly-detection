import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, User, KeyRound, Eye, EyeOff, MapPin, Monitor, Clock, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import GlassCard from "@/components/GlassCard";
import PasswordStrengthMeter from "@/components/PasswordStrengthMeter";
import RiskGauge from "@/components/RiskGauge";
import ExplainableAIPanel from "@/components/ExplainableAIPanel";
import { generateUserProfile } from "@/lib/mockData";

type LoginState = "idle" | "loading" | "risk-check" | "otp" | "success";

export default function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [state, setState] = useState<LoginState>("idle");
  const [risk, setRisk] = useState(0);
  const [otp, setOtp] = useState("");
  const [reasons, setReasons] = useState<string[]>([]);
  const [profile, setProfile] = useState<ReturnType<typeof generateUserProfile> | null>(null);

  const handleLogin = () => {
    if (!username.trim() || !password.trim()) return;
    setState("loading");

    setTimeout(() => {
      const p = generateUserProfile(username);
      setProfile(p);
      const r = Math.floor(Math.random() * 100);
      setRisk(r);

      const flagReasons: string[] = [];
      if (r > 40) {
        if (Math.random() > 0.4) flagReasons.push("New device detected");
        if (Math.random() > 0.4) flagReasons.push("Unusual location");
        if (Math.random() > 0.5) flagReasons.push("Login outside normal hours");
        if (flagReasons.length === 0) flagReasons.push("Behavioral anomaly");
      }
      setReasons(flagReasons);

      if (r > 60) {
        setState("otp");
      } else {
        setState("risk-check");
        setTimeout(() => setState("success"), 2000);
      }
    }, 1500);
  };

  const handleOtp = () => {
    if (otp.length < 4) return;
    setState("loading");
    setTimeout(() => {
      setState("success");
    }, 1000);
  };

  const handleSimulateAttack = () => {
    setUsername("attacker_bot");
    setPassword("password123");
    setState("loading");
    setTimeout(() => {
      const p = generateUserProfile("attacker_bot");
      setProfile(p);
      setRisk(92);
      setReasons(["New device detected", "Unusual location", "Login outside normal hours", "Multiple failed attempts"]);
      setState("otp");
    }, 1500);
  };

  return (
    <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center py-8">
      <div className="w-full max-w-md space-y-5 animate-slide-up">
        {/* Header */}
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
            <p className="text-sm text-muted-foreground">Identity verified. Risk Score: {risk}%</p>

            {profile && (
              <div className="grid grid-cols-3 gap-3 pt-3 border-t border-border/50">
                <div className="text-center">
                  <Clock className="w-4 h-4 mx-auto text-muted-foreground mb-1" />
                  <p className="text-xs text-muted-foreground">Last Login</p>
                  <p className="text-xs font-medium">{new Date(profile.lastLogin).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</p>
                </div>
                <div className="text-center">
                  <Monitor className="w-4 h-4 mx-auto text-muted-foreground mb-1" />
                  <p className="text-xs text-muted-foreground">Device</p>
                  <p className="text-xs font-medium">{profile.lastDevice.split("/")[0]}</p>
                </div>
                <div className="text-center">
                  <MapPin className="w-4 h-4 mx-auto text-muted-foreground mb-1" />
                  <p className="text-xs text-muted-foreground">Location</p>
                  <p className="text-xs font-medium">{profile.lastLocation.split(",")[0]}</p>
                </div>
              </div>
            )}

            <Button className="w-full" onClick={() => navigate("/dashboard")}>
              Go to Dashboard
            </Button>
          </GlassCard>
        ) : (
          <>
            {/* Login Form */}
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
                  <Button className="w-full" onClick={handleLogin} disabled={!username || !password}>
                    Authenticate
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

            {/* OTP */}
            {state === "otp" && (
              <GlassCard className="border-warning/30 animate-slide-up space-y-4">
                <div className="flex items-center gap-2 text-warning">
                  <Shield className="w-5 h-5" />
                  <h3 className="font-semibold text-sm">Additional Verification Required</h3>
                </div>
                <p className="text-xs text-muted-foreground">
                  High risk score detected ({risk}%). Please enter the OTP sent to your registered device.
                </p>
                <div className="relative">
                  <div className="flex items-center justify-center">
                    <RiskGauge risk={risk} />
                  </div>
                </div>
                <Input
                  placeholder="Enter 6-digit OTP"
                  className="bg-secondary/50 border-border/50 text-center font-mono text-lg tracking-[0.5em]"
                  maxLength={6}
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/\D/g, ""))}
                />
                <Button className="w-full" onClick={handleOtp} disabled={otp.length < 4}>
                  Verify OTP
                </Button>
              </GlassCard>
            )}

            {/* Risk check animation */}
            {state === "risk-check" && (
              <GlassCard className="animate-slide-up text-center space-y-3">
                <div className="flex items-center justify-center">
                  <RiskGauge risk={risk} />
                </div>
                <p className="text-sm text-success font-medium">Low risk — Granting access...</p>
              </GlassCard>
            )}

            {/* Explainable AI */}
            {(state === "otp" || state === "risk-check") && reasons.length > 0 && (
              <ExplainableAIPanel reasons={reasons} risk={risk} />
            )}

            {/* Attack Simulation */}
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
