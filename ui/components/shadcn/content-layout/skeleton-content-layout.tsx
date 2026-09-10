import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

export const SkeletonContentLayout = () => {
  return (
    <div className="flex items-center gap-4">
      {/* Theme Switch Skeleton */}
      <Skeleton className="h-8 w-8 rounded-full" />

      {/* User Avatar Skeleton */}
      <Skeleton className="h-10 w-10 rounded-full" />
    </div>
  );
};
