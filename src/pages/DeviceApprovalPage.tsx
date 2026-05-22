import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CheckCircle2, ShieldAlert, XCircle } from "lucide-react";

import GlassCard from "@/components/GlassCard";
import { Button } from "@/components/ui/button";
import { approveDeviceLogin, denyDeviceLogin } from "@/lib/api";

type ApprovalState = "loading" | "approved" | "denied" | "error" | "idle";

export default function DeviceApprovalPage() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const action = params.get("action") ?? "approve";
  const [state, setState] = useState<ApprovalState>(token ? "loading" : "idle");
  const [message, setMessage] = useState(token ? "Validating approval token..." : "No approval token was provided.");

  useEffect(() => {
    if (!token) return;

    const run = async () => {
      try {
        const response = action === "deny" ? await denyDeviceLogin(token) : await approveDeviceLogin(token);
        setState(action === "deny" ? "denied" : "approved");
        setMessage(response.message);
      } catch (error) {
        setState("error");
        setMessage(error instanceof Error ? error.message : "Unable to process device approval.");
      }
    };

    void run();
  }, [action, token]);

  const Icon = state === "approved" ? CheckCircle2 : state === "denied" || state === "error" ? XCircle : ShieldAlert;
  const iconClass = state === "approved" ? "text-success bg-success/10" : state === "denied" || state === "error" ? "text-destructive bg-destructive/10" : "text-warning bg-warning/10";

  return (
    <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center py-8">
      <GlassCard glow className="w-full max-w-md text-center space-y-4 animate-slide-up">
        <div className={`w-16 h-16 rounded-full flex items-center justify-center mx-auto ${iconClass}`}>
          <Icon className="w-8 h-8" />
        </div>
        <h1 className="text-xl font-bold">
          {state === "approved" ? "Login Approved" : state === "denied" ? "Login Denied" : state === "loading" ? "Checking Login" : "Device Approval"}
        </h1>
        <p className="text-sm text-muted-foreground">{message}</p>
        <div className="flex gap-2">
          {token && state !== "approved" && action !== "deny" && (
            <Button variant="outline" className="flex-1" onClick={() => void denyDeviceLogin(token).then((result) => {
              setState("denied");
              setMessage(result.message);
            })}>
              Deny
            </Button>
          )}
          <Button asChild className="flex-1">
            <Link to="/">Back to Login</Link>
          </Button>
        </div>
      </GlassCard>
    </div>
  );
}
