import { Card, CardBody, CardHeader, Skeleton } from "@nextui-org/react";

export const SkeletonFindingsBySeverityChart = () => {
  return (
    <div className="flex h-full flex-col">
      <div className="mb-4">
        <Skeleton className="h-4 w-1/3 rounded-lg">
          <div className="h-4 bg-default-200"></div>
        </Skeleton>
      </div>
      <Card className="flex-1 h-full">
      <CardBody className="flex h-full items-center justify-center p-6">
        <div className="flex flex-col gap-4 w-full">
          {/* Critical */}
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-1/4 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
            <Skeleton className="h-4 w-12 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
          </div>
          {/* High */}
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-2/4 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
            <Skeleton className="h-4 w-12 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
          </div>
          {/* Medium */}
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-3/4 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
            <Skeleton className="h-4 w-12 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
          </div>
          {/* Low */}
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-1/2 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
            <Skeleton className="h-4 w-12 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
          </div>
          {/* Informational */}
          <div className="flex items-center gap-2">
            <Skeleton className="h-4 w-1/6 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
            <Skeleton className="h-4 w-12 rounded-lg">
              <div className="h-4 bg-default-200"></div>
            </Skeleton>
          </div>
        </div>
      </CardBody>
    </Card>
    </div>
  );
};
