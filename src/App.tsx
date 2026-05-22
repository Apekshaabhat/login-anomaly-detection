import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import AppLayout from "@/components/AppLayout";
import { AuthProvider } from "@/lib/auth-store";
import LoginPage from "@/pages/LoginPage";
import DashboardPage from "@/pages/DashboardPage";
import BehaviorPage from "@/pages/BehaviorPage";
import AdminPage from "@/pages/AdminPage";
import ModelPage from "@/pages/ModelPage";
import SecurityPage from "@/pages/SecurityPage";
import AISecurityPage from "@/pages/AISecurityPage";
import DevicesPage from "@/pages/DevicesPage";
import DeviceApprovalPage from "@/pages/DeviceApprovalPage";
import NotFound from "@/pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <AppLayout>
            <Routes>
              <Route path="/" element={<LoginPage />} />
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/security" element={<SecurityPage />} />
              <Route path="/ai-security" element={<AISecurityPage />} />
              <Route path="/devices" element={<DevicesPage />} />
              <Route path="/approval" element={<DeviceApprovalPage />} />
              <Route path="/device-approval" element={<DeviceApprovalPage />} />
              <Route path="/behavior" element={<BehaviorPage />} />
              <Route path="/admin" element={<AdminPage />} />
              <Route path="/model" element={<ModelPage />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </AppLayout>
        </BrowserRouter>
      </TooltipProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
