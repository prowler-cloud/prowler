import type { ReactNode } from "react";

import { ProwlerBrand } from "@/components/icons";

interface PublicAuthShellProps {
  children: ReactNode;
}

export const PublicAuthShell = ({ children }: PublicAuthShellProps) => {
  return (
    <div className="relative min-h-screen">
      <div className="pointer-events-none absolute top-8 left-1/2 z-20 w-[200px] -translate-x-1/2">
        <ProwlerBrand className="w-full" />
      </div>
      {children}
    </div>
  );
};
