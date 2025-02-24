import { Skeleton } from "@nextui-org/react";

export const SkeletonMainLayout = () => {
  return (
    <div className="flex h-screen w-full justify-center overflow-hidden">
      {/* Sidebar Skeleton */}
      <Skeleton className="h-full w-64 rounded-lg dark:bg-prowler-blue-800">
        <div className="h-full bg-default-200"></div>
      </Skeleton>

      {/* Main Content Skeleton */}
      <div className="flex flex-1 flex-col overflow-y-auto px-6 py-4">
        <div className="flex items-start justify-between">
          {/* Page Content Skeleton */}
          <Skeleton className="h-12 w-1/3 rounded-lg dark:bg-prowler-blue-800">
            <div className="h-12 bg-default-200"></div>
          </Skeleton>

          {/* Top Right - Theme Switch & User Nav */}
          <div className="flex space-x-4">
            <Skeleton className="h-8 w-8 rounded-full dark:bg-prowler-blue-800">
              <div className="h-8 w-8 bg-default-200"></div>
            </Skeleton>
            <Skeleton className="h-10 w-10 rounded-full dark:bg-prowler-blue-800">
              <div className="h-10 w-10 bg-default-200"></div>
            </Skeleton>
          </div>
        </div>

        <Skeleton className="mt-6 h-[calc(100vh-6rem)] w-full rounded-lg dark:bg-prowler-blue-800">
          <div className="h-full bg-default-200"></div>
        </Skeleton>
      </div>
    </div>
  );
};
