import { Card, CardBody, CardHeader, Skeleton } from "@nextui-org/react";

export const SkeletonFindingsByStatusChart = () => {
  return (
    <div className="flex h-full flex-col">
      <div className="mb-4">
        <Skeleton className="h-4 w-1/4 rounded-lg">
          <div className="h-4 bg-default-200"></div>
        </Skeleton>
      </div>
      <Card className="flex-1 h-full">
      <CardBody className="flex h-full flex-col items-center justify-between p-6">
        <div className="flex h-full flex-col items-center justify-between">
          {/* Circle Chart Skeleton */}
          <Skeleton className="aspect-square h-[200px] w-[200px] rounded-full flex-shrink-0">
            <div className="h-[200px] w-[200px] bg-default-200"></div>
          </Skeleton>

          {/* Text Details Skeleton */}
          <div className="flex flex-1 flex-col justify-center gap-3 pt-4">
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
    </div>
  );
};
