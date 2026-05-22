import { useEffect, useMemo, useRef } from "react";

import { sendBehaviorTelemetry } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

function getSessionId() {
  const existing = window.sessionStorage.getItem("adaptive_session_id");
  if (existing) return existing;
  const next = crypto.randomUUID ? crypto.randomUUID() : `session-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  window.sessionStorage.setItem("adaptive_session_id", next);
  return next;
}

function mean(values: number[]) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

function std(values: number[]) {
  if (values.length < 2) return 0;
  const avg = mean(values);
  return Math.sqrt(mean(values.map((value) => (value - avg) ** 2)));
}

function deviceFingerprint() {
  return `${navigator.platform}-${navigator.userAgent}-${window.screen.width}x${window.screen.height}`.replace(/\s+/g, "-").slice(0, 180);
}

export function useBehaviorTelemetry() {
  const { isAuthenticated } = useAuthStore();
  const sessionId = useMemo(getSessionId, []);
  const lastMouse = useRef<{ x: number; y: number; t: number } | null>(null);
  const mouseVelocities = useRef<number[]>([]);
  const keyTimings = useRef<number[]>([]);
  const corrections = useRef(0);
  const keyCount = useRef(0);
  const scrollVelocities = useRef<number[]>([]);
  const maxScrollDepth = useRef(0);
  const lastScroll = useRef<{ y: number; t: number } | null>(null);
  const replayEventCount = useRef(0);
  const focusChanges = useRef(0);
  const activeStartedAt = useRef(Date.now());
  const lastActivityAt = useRef(Date.now());

  useEffect(() => {
    const onMouseMove = (event: MouseEvent) => {
      const now = Date.now();
      if (lastMouse.current) {
        const distance = Math.hypot(event.clientX - lastMouse.current.x, event.clientY - lastMouse.current.y);
        const seconds = Math.max((now - lastMouse.current.t) / 1000, 0.01);
        mouseVelocities.current.push(distance / seconds);
        if (mouseVelocities.current.length > 120) mouseVelocities.current.shift();
      }
      lastMouse.current = { x: event.clientX, y: event.clientY, t: now };
      lastActivityAt.current = now;
    };
    const onKeyDown = (event: KeyboardEvent) => {
      const now = Date.now();
      keyCount.current += 1;
      if (event.key === "Backspace" || event.key === "Delete") corrections.current += 1;
      keyTimings.current.push(now);
      if (keyTimings.current.length > 120) keyTimings.current.shift();
      lastActivityAt.current = now;
    };
    const onFocus = () => {
      focusChanges.current += 1;
      lastActivityAt.current = Date.now();
    };
    const onScroll = () => {
      const now = Date.now();
      const maxScrollable = Math.max(document.documentElement.scrollHeight - window.innerHeight, 1);
      const y = window.scrollY || document.documentElement.scrollTop || 0;
      maxScrollDepth.current = Math.max(maxScrollDepth.current, Math.min(1, y / maxScrollable));
      if (lastScroll.current) {
        const seconds = Math.max((now - lastScroll.current.t) / 1000, 0.01);
        scrollVelocities.current.push(Math.abs(y - lastScroll.current.y) / seconds);
        if (scrollVelocities.current.length > 120) scrollVelocities.current.shift();
      }
      lastScroll.current = { y, t: now };
      replayEventCount.current += 1;
      lastActivityAt.current = now;
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onFocus);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("blur", onFocus);
    };
  }, []);

  useEffect(() => {
    if (!isAuthenticated) return;

    const intervalId = window.setInterval(() => {
      const now = Date.now();
      const keyIntervals = keyTimings.current.slice(1).map((value, index) => value - keyTimings.current[index]);
      const activeSeconds = (now - activeStartedAt.current) / 1000;
      const idleSeconds = Math.max(0, (now - lastActivityAt.current) / 1000);
      const mouseIdleRatio = activeSeconds > 0 ? Math.min(1, idleSeconds / activeSeconds) : 0;
      const replayAnomalyScore = Math.min(
        100,
        focusChanges.current * 2
          + (mouseIdleRatio > 0.85 ? 15 : 0)
          + (scrollVelocities.current.length > 80 ? 8 : 0)
          + (keyCount.current > 250 ? 8 : 0),
      );

      void sendBehaviorTelemetry({
        session_id: sessionId,
        device_fingerprint: deviceFingerprint(),
        page_path: window.location.pathname,
        typing_speed: keyCount.current ? keyCount.current / Math.max(activeSeconds / 60, 0.1) : null,
        typing_variance: std(keyIntervals),
        key_hold_mean: null,
        key_flight_mean: mean(keyIntervals),
        correction_rate: keyCount.current ? corrections.current / keyCount.current : 0,
        mouse_velocity_mean: mean(mouseVelocities.current),
        mouse_velocity_std: std(mouseVelocities.current),
        mouse_idle_ratio: mouseIdleRatio,
        scroll_depth: maxScrollDepth.current,
        scroll_velocity_mean: mean(scrollVelocities.current),
        replay_event_count: replayEventCount.current + keyCount.current + mouseVelocities.current.length,
        replay_anomaly_score: replayAnomalyScore,
        focus_change_count: focusChanges.current,
        active_seconds: activeSeconds,
        extra: { path: window.location.pathname, replay_source: "lightweight_rrweb_ready" },
      }).catch(() => {
        // Telemetry must never break the user's current session.
      });

      corrections.current = 0;
      keyCount.current = 0;
      keyTimings.current = [];
      mouseVelocities.current = [];
      scrollVelocities.current = [];
      maxScrollDepth.current = 0;
      replayEventCount.current = 0;
      focusChanges.current = 0;
      activeStartedAt.current = now;
      lastActivityAt.current = now;
    }, 30000);

    return () => window.clearInterval(intervalId);
  }, [isAuthenticated, sessionId]);
}
