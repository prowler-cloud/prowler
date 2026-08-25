import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

import { ComplianceFrameworkGrid } from "../compliance-framework-grid";

export const ComplianceSkeletonGrid = () => {
  return (
    <ComplianceFrameworkGrid>
      {[...Array(28)].map((_, index) => (
        <Skeleton key={index} className="h-28 rounded-xl" />
      ))}
    </ComplianceFrameworkGrid>
  );
};
