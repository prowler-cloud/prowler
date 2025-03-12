import { Card, CardBody, CardHeader, Skeleton } from "@nextui-org/react";

export const SkeletonFindingsByStatusChart = () => {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-6 w-1/4 rounded-lg">
          <div className="h-6 bg-default-200"></div>
        </Skeleton>
      </CardHeader>
      <CardBody>
        <div className="flex items-center gap-6">
          {/* Circle Chart Skeleton */}
          <Skeleton className="aspect-square h-[150px] w-[150px] rounded-full">
            <div className="h-[150px] w-[150px] bg-default-200"></div>
          </Skeleton>

          {/* Text Details Skeleton */}
          <div className="flex flex-col gap-4">
            {/* Pass Findings */}
            <div className="flex flex-col gap-2">
              <div className="flex items-center space-x-2">
                <Skeleton className="h-5 w-16 rounded-lg">
                  <div className="h-5 bg-default-200"></div>
                </Skeleton>
                <Skeleton className="h-5 w-10 rounded-lg">
                  <div className="h-5 bg-default-200"></div>
                </Skeleton>
              </div>
              <Skeleton className="h-4 w-48 rounded-lg">
                <div className="h-4 bg-default-200"></div>
              </Skeleton>
            </div>

            {/* Fail Findings */}
            <div className="flex flex-col gap-2">
              <div className="flex items-center space-x-2">
                <Skeleton className="h-5 w-16 rounded-lg">
                  <div className="h-5 bg-default-200"></div>
                </Skeleton>
                <Skeleton className="h-5 w-10 rounded-lg">
                  <div className="h-5 bg-default-200"></div>
                </Skeleton>
              </div>
              <Skeleton className="h-4 w-48 rounded-lg">
                <div className="h-4 bg-default-200"></div>
              </Skeleton>
            </div>
          </div>
        </div>
      </CardBody>
    </Card>
  );
};
