import { Skeleton } from "@nextui-org/react";

export const SkeletonContentLayout = () => {
  return (
    <div className="flex items-center space-x-4">
      {/* Theme Switch Skeleton */}
      <Skeleton className="h-8 w-8 rounded-full dark:bg-prowler-blue-800">
        <div className="h-8 w-8 bg-default-200"></div>
      </Skeleton>

      {/* User Avatar Skeleton */}
      <Skeleton className="h-10 w-10 rounded-full dark:bg-prowler-blue-800">
        <div className="h-10 w-10 bg-default-200"></div>
      </Skeleton>
    </div>
  );
};
