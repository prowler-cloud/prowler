import { Skeleton } from "@nextui-org/react";

export const SkeletonProfile = () => {
  return (
    <div className="flex items-center space-x-2">
      <Skeleton className="h-10 w-10 rounded-full">
        <div className="h-10 w-10 rounded-full bg-default-200"></div>
      </Skeleton>
      <div className="flex flex-col space-y-1">
        <Skeleton className="h-4 w-24 rounded-lg">
          <div className="h-4 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="h-3 w-24 rounded-lg">
          <div className="h-3 bg-default-200"></div>
        </Skeleton>
      </div>
    </div>
  );
};
