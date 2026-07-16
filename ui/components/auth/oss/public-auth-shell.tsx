import type { ReactNode } from "react";

interface PublicAuthShellProps {
  children: ReactNode;
}

export const PublicAuthShell = ({ children }: PublicAuthShellProps) => {
  return <div className="relative min-h-screen">{children}</div>;
};
