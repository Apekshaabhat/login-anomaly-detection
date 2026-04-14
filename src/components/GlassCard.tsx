import { cn } from "@/lib/utils";

interface Props {
  children: React.ReactNode;
  className?: string;
  glow?: boolean;
}

export default function GlassCard({ children, className, glow }: Props) {
  return (
    <div className={cn("glass-card p-5", glow && "cyber-glow", className)}>
      {children}
    </div>
  );
}
