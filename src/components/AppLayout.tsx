import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Shield, LayoutDashboard, Brain, Settings, Activity,
  Menu, X, Lock
} from "lucide-react";

const navItems = [
  { path: "/", label: "Login", icon: Lock },
  { path: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { path: "/behavior", label: "Behavior", icon: Brain },
  { path: "/admin", label: "Admin", icon: Settings },
  { path: "/model", label: "Model", icon: Activity },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top bar */}
      <header className="h-14 border-b border-border/50 glass-card flex items-center px-4 gap-3 sticky top-0 z-50">
        <button
          className="md:hidden p-1.5 rounded-lg hover:bg-secondary transition-colors"
          onClick={() => setMobileOpen(!mobileOpen)}
        >
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
        <Shield className="w-6 h-6 text-primary" />
        <span className="font-semibold text-sm tracking-wide gradient-text hidden sm:inline">
          Adaptive Login Security
        </span>
        <nav className="hidden md:flex items-center gap-1 ml-6">
          {navItems.map((item) => {
            const active = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-all duration-200 ${
                  active
                    ? "bg-primary/10 text-primary font-medium"
                    : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                }`}
              >
                <item.icon className="w-4 h-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="ml-auto flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
          <span className="text-xs text-muted-foreground">System Active</span>
        </div>
      </header>

      {/* Mobile nav */}
      {mobileOpen && (
        <div className="md:hidden border-b border-border/50 glass-card animate-slide-up">
          <nav className="flex flex-col p-2 gap-1">
            {navItems.map((item) => {
              const active = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setMobileOpen(false)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-all ${
                    active
                      ? "bg-primary/10 text-primary font-medium"
                      : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                  }`}
                >
                  <item.icon className="w-4 h-4" />
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>
      )}

      <main className="flex-1 p-4 md:p-6 max-w-7xl mx-auto w-full">{children}</main>
    </div>
  );
}
