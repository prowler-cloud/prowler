import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

export const ComplianceSkeletonGrid = () => {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
      {[...Array(28)].map((_, index) => (
        <Skeleton key={index} className="h-28 rounded-xl" />
      ))}
    </div>
  );
};
