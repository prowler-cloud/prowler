import { Card, CardBody, CardHeader } from "@heroui/card";
import { Skeleton } from "@heroui/skeleton";

export const SkeletonProvidersOverview = () => {
  const rows = 4;

  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-6 w-1/3 rounded-lg">
          <div className="bg-default-200 h-6"></div>
        </Skeleton>
      </CardHeader>
      <CardBody>
        <div className="grid grid-cols-1 gap-4">
          {/* Header Skeleton */}
          <div className="grid grid-cols-4 border-b pb-2 text-sm font-semibold">
            <Skeleton className="h-5 w-full rounded-lg">
              <div className="bg-default-200 h-5"></div>
            </Skeleton>
            <Skeleton className="h-5 w-full rounded-lg">
              <div className="bg-default-200 h-5"></div>
            </Skeleton>
            <Skeleton className="h-5 w-full rounded-lg">
              <div className="bg-default-200 h-5"></div>
            </Skeleton>
            <Skeleton className="h-5 w-full rounded-lg">
              <div className="bg-default-200 h-5"></div>
            </Skeleton>
          </div>

          {/* Row Skeletons */}
          {Array.from({ length: rows }).map((_, index) => (
            <div
              key={index}
              className="grid grid-cols-4 items-center border-b py-2 text-sm"
            >
              {/* Provider Name */}
              <div className="flex items-center gap-2">
                <Skeleton className="h-5 w-5 rounded-lg">
                  <div className="bg-default-200 h-5 w-5"></div>
                </Skeleton>
                <Skeleton className="h-5 w-1/3 rounded-lg">
                  <div className="bg-default-200 h-5"></div>
                </Skeleton>
              </div>
              {/* Percent Passing */}
              <Skeleton className="h-5 w-1/4 rounded-lg">
                <div className="bg-default-200 h-5"></div>
              </Skeleton>
              {/* Failing Checks */}
              <Skeleton className="h-5 w-1/4 rounded-lg">
                <div className="bg-default-200 h-5"></div>
              </Skeleton>
              {/* Total Resources */}
              <Skeleton className="h-5 w-1/4 rounded-lg">
                <div className="bg-default-200 h-5"></div>
              </Skeleton>
            </div>
          ))}
        </div>
      </CardBody>
    </Card>
  );
};
