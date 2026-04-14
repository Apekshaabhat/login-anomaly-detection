export interface LoginLog {
  id: string;
  user: string;
  time: string;
  location: string;
  device: string;
  risk: number;
  status: "safe" | "suspicious" | "blocked";
  ip: string;
  lat: number;
  lng: number;
  reasons?: string[];
}

export interface UserProfile {
  username: string;
  typicalLoginTime: string;
  frequentLocations: string[];
  devicesUsed: string[];
  trustScore: number;
  isNewUser: boolean;
  lastLogin: string;
  lastDevice: string;
  lastLocation: string;
  trustHistory: { date: string; score: number }[];
}

export interface Alert {
  id: string;
  time: string;
  message: string;
  severity: "low" | "medium" | "high" | "critical";
  resolved: boolean;
}

export interface ModelInfo {
  lastTrained: string;
  accuracy: number;
  dataSize: number;
  version: string;
  driftDetected: boolean;
  driftScore: number;
}

const locations = ["New York, US", "London, UK", "Tokyo, JP", "Berlin, DE", "Sydney, AU", "Mumbai, IN", "São Paulo, BR", "Toronto, CA"];
const devices = ["Chrome / Windows 11", "Safari / macOS 14", "Firefox / Ubuntu 22", "Edge / Windows 10", "Chrome / Android 14", "Safari / iOS 17"];
const users = ["alex.chen", "sarah.jones", "mike.torres", "emma.wilson", "raj.patel", "lisa.zhang", "james.kim", "olivia.brown"];
const coords: Record<string, [number, number]> = {
  "New York, US": [40.71, -74.01],
  "London, UK": [51.51, -0.13],
  "Tokyo, JP": [35.68, 139.69],
  "Berlin, DE": [52.52, 13.41],
  "Sydney, AU": [-33.87, 151.21],
  "Mumbai, IN": [19.08, 72.88],
  "São Paulo, BR": [-23.55, -46.63],
  "Toronto, CA": [43.65, -79.38],
};

function randomFrom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateTime(hoursAgo: number): string {
  const d = new Date(Date.now() - hoursAgo * 3600000);
  return d.toISOString();
}

export function generateLoginLogs(count: number = 50): LoginLog[] {
  return Array.from({ length: count }, (_, i) => {
    const loc = randomFrom(locations);
    const risk = Math.random() * 100;
    const status: LoginLog["status"] = risk > 75 ? "blocked" : risk > 50 ? "suspicious" : "safe";
    const reasons: string[] = [];
    if (risk > 50) {
      if (Math.random() > 0.5) reasons.push("New device detected");
      if (Math.random() > 0.5) reasons.push("Unusual location");
      if (Math.random() > 0.4) reasons.push("Login outside normal hours");
      if (Math.random() > 0.6) reasons.push("Multiple failed attempts");
      if (reasons.length === 0) reasons.push("Behavioral anomaly");
    }
    return {
      id: `log-${i}`,
      user: randomFrom(users),
      time: generateTime(i * 0.5 + Math.random() * 2),
      location: loc,
      device: randomFrom(devices),
      risk: Math.round(risk),
      status,
      ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      lat: coords[loc][0] + (Math.random() - 0.5) * 2,
      lng: coords[loc][1] + (Math.random() - 0.5) * 2,
      reasons,
    };
  }).sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());
}

export function generateUserProfile(username?: string): UserProfile {
  const u = username || randomFrom(users);
  return {
    username: u,
    typicalLoginTime: "09:00 - 18:00 EST",
    frequentLocations: ["New York, US", "Toronto, CA"],
    devicesUsed: ["Chrome / Windows 11", "Safari / iOS 17"],
    trustScore: 72 + Math.floor(Math.random() * 25),
    isNewUser: Math.random() > 0.8,
    lastLogin: generateTime(Math.random() * 24),
    lastDevice: randomFrom(devices),
    lastLocation: randomFrom(locations),
    trustHistory: Array.from({ length: 30 }, (_, i) => ({
      date: new Date(Date.now() - (29 - i) * 86400000).toISOString().split("T")[0],
      score: 60 + Math.floor(Math.random() * 35),
    })),
  };
}

export function generateAlerts(count: number = 20): Alert[] {
  const messages = [
    "Brute force attempt detected",
    "Login from new country",
    "Credential stuffing pattern",
    "Impossible travel detected",
    "Multiple account lockouts",
    "Suspicious IP range activity",
    "Token replay attack attempt",
    "Session hijacking pattern",
  ];
  const severities: Alert["severity"][] = ["low", "medium", "high", "critical"];
  return Array.from({ length: count }, (_, i) => ({
    id: `alert-${i}`,
    time: generateTime(i * 1.2),
    message: randomFrom(messages),
    severity: randomFrom(severities),
    resolved: Math.random() > 0.4,
  })).sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime());
}

export function generateModelInfo(): ModelInfo {
  return {
    lastTrained: generateTime(48 + Math.random() * 72),
    accuracy: 94.2 + Math.random() * 4,
    dataSize: 125000 + Math.floor(Math.random() * 50000),
    version: "2.4.1",
    driftDetected: Math.random() > 0.5,
    driftScore: Math.random() * 0.3,
  };
}

export function generateRiskTimeline(): { time: string; risk: number; baseline: number }[] {
  return Array.from({ length: 24 }, (_, i) => ({
    time: `${String(i).padStart(2, "0")}:00`,
    risk: 15 + Math.floor(Math.random() * 60),
    baseline: 25,
  }));
}
