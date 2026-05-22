import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Clock, Eye, EyeOff, KeyRound, MapPin, Shield, User, Zap } from "lucide-react";

import ExplainableAIPanel from "@/components/ExplainableAIPanel";
import GlassCard from "@/components/GlassCard";
import PasswordStrengthMeter from "@/components/PasswordStrengthMeter";
import RiskGauge from "@/components/RiskGauge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { toast } from "@/components/ui/sonner";
import { analyzeLogin, fetchChallengeStatus, loginRequest, resendOtp, verifyOtp } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

type LoginState = "idle" | "loading" | "risk-check" | "otp" | "approval-pending" | "success";
type BrowserLocation = {
  lat: number;
  lon: number;
  ip?: string;
  source: "browser" | "ip" | "demo";
  accuracy?: number;
};

function getDeviceId() {
  const platform = navigator.platform || "web";
  const agent = navigator.userAgent || "browser";
  const resolution = `${window.screen.width}x${window.screen.height}`;
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  return `${platform}-${agent}-${resolution}-${timezone}`.replace(/\s+/g, "-").slice(0, 180);
}

function hashString(value: string) {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(index);
    hash |= 0;
  }
  return Math.abs(hash).toString(16);
}

function getBrowser() {
  const agent = navigator.userAgent;
  if (agent.includes("Edg")) return "Microsoft Edge";
  if (agent.includes("Chrome")) return "Chrome";
  if (agent.includes("Firefox")) return "Firefox";
  if (agent.includes("Safari")) return "Safari";
  return "Unknown browser";
}

function getOS() {
  const platform = navigator.platform.toLowerCase();
  const agent = navigator.userAgent.toLowerCase();
  if (platform.includes("win")) return "Windows";
  if (platform.includes("mac")) return "macOS";
  if (agent.includes("android")) return "Android";
  if (/iphone|ipad|ipod/.test(agent)) return "iOS";
  if (platform.includes("linux")) return "Linux";
  return "Unknown OS";
}

function getDeviceType() {
  if (/Mobi|Android|iPhone|iPad/i.test(navigator.userAgent)) return "mobile";
  return "desktop";
}

function getDeviceMetadata() {
  const hardware = [
    navigator.hardwareConcurrency,
    (navigator as Navigator & { deviceMemory?: number }).deviceMemory,
    window.screen.colorDepth,
    window.devicePixelRatio,
  ].join(":");
  return {
    browser: getBrowser(),
    os: getOS(),
    device_type: getDeviceType(),
    screen_resolution: `${window.screen.width}x${window.screen.height}`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    hardware_fingerprint: hashString(hardware),
    user_agent_hash: hashString(navigator.userAgent),
  };
}

function formatMfaMethod(method?: string | null) {
  if (method === "email_otp") return "Email OTP";
  if (method === "sms_otp") return "SMS OTP";
  if (method === "totp_or_email") return "Authenticator app or Email OTP";
  return "adaptive verification";
}

function getBrowserLocation(): Promise<BrowserLocation> {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Browser location is not available."));
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        resolve({
          lat: Number(position.coords.latitude.toFixed(6)),
          lon: Number(position.coords.longitude.toFixed(6)),
          source: "browser",
          accuracy: Math.round(position.coords.accuracy),
        });
      },
      () => reject(new Error("Location permission was not granted.")),
      {
        enableHighAccuracy: true,
        timeout: 8000,
        maximumAge: 300000,
      },
    );
  });
}

async function getIpLocation(): Promise<BrowserLocation> {
  const response = await fetch("https://ipapi.co/json/");
  if (!response.ok) {
    throw new Error("IP location lookup failed.");
  }
  const data = await response.json();
  const lat = Number(data.latitude);
  const lon = Number(data.longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    throw new Error("IP location was not available.");
  }
  return {
    lat: Number(lat.toFixed(6)),
    lon: Number(lon.toFixed(6)),
    ip: typeof data.ip === "string" ? data.ip : undefined,
    source: "ip",
  };
}

export default function LoginPage() {
  const navigate = useNavigate();
  const auth = useAuthStore();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [rememberDevice, setRememberDevice] = useState(true);
  const [showPw, setShowPw] = useState(false);
  const [state, setState] = useState<LoginState>("idle");
  const [risk, setRisk] = useState(0);
  const [level, setLevel] = useState<"LOW" | "MEDIUM" | "HIGH">("LOW");
  const [otp, setOtp] = useState("");
  const [debugOtp, setDebugOtp] = useState<string | null>(null);
  const [reasons, setReasons] = useState<string[]>([]);
  const [verificationToken, setVerificationToken] = useState<string | null>(null);
  const [mfaMethod, setMfaMethod] = useState<string | null>(null);
  const [trackedIp, setTrackedIp] = useState<string | null>(null);
  const [approvalMessage, setApprovalMessage] = useState<string | null>(null);
  const [fraudProbability, setFraudProbability] = useState(0);
  const [sessionTrust, setSessionTrust] = useState(100);
  const [recommendedAction, setRecommendedAction] = useState<string | null>(null);
  const [browserLocation, setBrowserLocation] = useState<BrowserLocation | null>(null);
  const [locationStatus, setLocationStatus] = useState<"idle" | "loading" | "ready" | "blocked">("idle");

  const analysisPayload = useMemo(() => {
    const now = new Date();
    const fallbackLocation: BrowserLocation = { lat: 19.076, lon: 72.8777, source: "demo" };
    const location = browserLocation ?? fallbackLocation;
    return {
      login_hour: Number((now.getHours() + now.getMinutes() / 60).toFixed(2)),
      location_lat: location.lat,
      location_lon: location.lon,
      typing_speed: Math.max(1, Number((password.length / 2.4).toFixed(2))),
      failed_attempts: username.toLowerCase().includes("attacker") ? 6 : 0,
      device_id: getDeviceId(),
      ip_address: location.ip ?? "127.0.0.1",
    };
  }, [browserLocation, password, username]);

  const syncRiskState = (payload: { risk_score: number; level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; reasons: string[] }) => {
    setRisk(Math.round(payload.risk_score));
    setLevel(payload.level === "CRITICAL" ? "HIGH" : payload.level);
    setReasons(payload.reasons);
  };

  useEffect(() => {
    if (state !== "approval-pending" || !verificationToken) return;

    const intervalId = window.setInterval(async () => {
      try {
        const status = await fetchChallengeStatus(verificationToken);
        if (status.access_token) {
          auth.setTokens(status.access_token, status.refresh_token);
          setState("success");
          toast.success("Device approved. Login completed.");
          window.clearInterval(intervalId);
        } else if (status.challenge_state === "denied" || status.challenge_state === "expired") {
          setState("risk-check");
          toast.error(`Login ${status.challenge_state}.`);
          window.clearInterval(intervalId);
        } else {
          setApprovalMessage(status.device_approved ? "Device approved. Finalizing session..." : "Waiting for approval from your email.");
        }
      } catch (error) {
        setApprovalMessage(error instanceof Error ? error.message : "Waiting for device approval.");
      }
    }, 3000);

    return () => window.clearInterval(intervalId);
  }, [auth, state, verificationToken]);

  useEffect(() => {
    if (locationStatus !== "idle") return;
    setLocationStatus("loading");
    getBrowserLocation()
      .then((location) => {
        setBrowserLocation(location);
        setLocationStatus("ready");
      })
      .catch(() => {
        getIpLocation()
          .then((location) => {
            setBrowserLocation(location);
            setLocationStatus("ready");
          })
          .catch(() => {
            setLocationStatus("blocked");
          });
      });
  }, [locationStatus]);

  const handleLocationRefresh = async (mode: "browser" | "ip" = "browser") => {
    setLocationStatus("loading");
    try {
      const location = mode === "ip" ? await getIpLocation() : await getBrowserLocation();
      setBrowserLocation(location);
      setLocationStatus("ready");
      toast.success(mode === "ip" ? "IP location captured." : "Browser location captured.");
    } catch (error) {
      setLocationStatus("blocked");
      toast.error(error instanceof Error ? error.message : "Unable to capture location.");
    }
  };

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) {
      toast.error("Enter both username and password to continue.");
      return;
    }

    setState("loading");
    setDebugOtp(null);
    setVerificationToken(null);
      setMfaMethod(null);
      setTrackedIp(null);
      setApprovalMessage(null);
      setFraudProbability(0);
      setSessionTrust(100);
      setRecommendedAction(null);

    try {
      const deviceMetadata = getDeviceMetadata();
      const result = await loginRequest({
        username: username.trim(),
        password,
        remember_device: rememberDevice,
        ...deviceMetadata,
        ...analysisPayload,
      });

      syncRiskState(result);
      setMfaMethod(result.mfa_method ?? null);
      setTrackedIp(result.ip_address ?? null);
      setFraudProbability(result.fraud_probability ?? 0);
      setSessionTrust(result.session_trust_score ?? 100);
      setRecommendedAction(result.recommended_action ?? null);

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

      if (result.access_token) {
        auth.setTokens(result.access_token, result.refresh_token);
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
      const result = await verifyOtp(username.trim(), otp, verificationToken);
      setMfaMethod(result.mfa_method ?? mfaMethod);
      if (result.challenge_state === "pending_device_approval") {
        setState("approval-pending");
        setApprovalMessage("OTP accepted. Check your email to approve this device.");
        toast.warning("Device approval is still pending.");
        return;
      }
      if (result.access_token) {
        auth.setTokens(result.access_token, result.refresh_token);
      }
      setState("success");
      toast.success("OTP verified successfully.");
    } catch (error) {
      setState("otp");
      toast.error(error instanceof Error ? error.message : "OTP verification failed.");
    }
  };

  const handleResendOtp = async () => {
    if (!verificationToken) return;
    try {
      await resendOtp(verificationToken);
      toast.success("A new OTP was sent.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to resend OTP.");
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
              Verified with {mfaMethod ? formatMfaMethod(mfaMethod) : "password login"} at a {level.toLowerCase()} risk score of {risk}%.
            </p>
            {trackedIp && <p className="text-xs text-muted-foreground">Tracked IP: {trackedIp}</p>}
            <p className="text-xs text-muted-foreground">
              Session trust {Math.round(sessionTrust)}% - fraud probability {Math.round(fraudProbability * 100)}%
              {recommendedAction ? ` - ${recommendedAction.replace("_", " ")}` : ""}
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
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Checkbox checked={rememberDevice} onCheckedChange={(checked) => setRememberDevice(Boolean(checked))} />
                  Remember this device after verification
                </label>
                <div className="flex items-center justify-between gap-3 rounded-md border border-border/50 bg-secondary/30 px-3 py-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <MapPin className={`w-4 h-4 shrink-0 ${locationStatus === "ready" ? "text-success" : "text-muted-foreground"}`} />
                    <p className="text-xs text-muted-foreground truncate">
                      {locationStatus === "ready" && browserLocation
                        ? `${browserLocation.source === "ip" ? "IP" : "Browser"} location ${browserLocation.lat}, ${browserLocation.lon}`
                        : locationStatus === "loading"
                          ? "Checking login location"
                          : "Using demo fallback location"}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button type="button" size="sm" variant="outline" className="h-7 text-xs" onClick={() => handleLocationRefresh("ip")}>
                      Use IP
                    </Button>
                    <Button type="button" size="sm" variant="outline" className="h-7 text-xs" onClick={() => handleLocationRefresh("browser")}>
                      Use GPS
                    </Button>
                  </div>
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
                  Risk score {risk}% ({level}). MFA method: {formatMfaMethod(mfaMethod)}.
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
                <Button className="w-full" variant="outline" onClick={handleResendOtp}>
                  Resend OTP
                </Button>
              </GlassCard>
            )}

            {state === "approval-pending" && (
              <GlassCard className="border-warning/30 animate-slide-up space-y-4 text-center">
                <div className="w-14 h-14 rounded-full bg-warning/10 flex items-center justify-center mx-auto">
                  <Clock className="w-7 h-7 text-warning" />
                </div>
                <h3 className="font-semibold text-sm">Device Approval Pending</h3>
                <p className="text-xs text-muted-foreground">
                  {approvalMessage ?? "Approve or deny this login from the security email we sent."}
                </p>
                <div className="flex items-center justify-center">
                  <RiskGauge risk={risk} />
                </div>
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
