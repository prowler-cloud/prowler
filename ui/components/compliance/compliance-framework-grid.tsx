import type { PropsWithChildren } from "react";

export const ComplianceFrameworkGrid = ({ children }: PropsWithChildren) => (
  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
    {children}
  </div>
);
