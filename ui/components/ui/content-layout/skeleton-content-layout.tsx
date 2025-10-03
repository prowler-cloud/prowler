import { Skeleton } from "@heroui/skeleton";

export const SkeletonContentLayout = () => {
  return (
    <div className="flex items-center gap-4">
      {/* Theme Switch Skeleton */}
      <Skeleton className="dark:bg-prowler-blue-800 h-8 w-8 rounded-full">
        <div className="bg-default-200 h-8 w-8"></div>
      </Skeleton>

      {/* User Avatar Skeleton */}
      <Skeleton className="dark:bg-prowler-blue-800 h-10 w-10 rounded-full">
        <div className="bg-default-200 h-10 w-10"></div>
      </Skeleton>
    </div>
  );
};
