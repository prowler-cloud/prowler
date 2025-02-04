import { Card, CardBody, CardHeader, Skeleton } from "@nextui-org/react";

export const SkeletonFindingsBySeverityChart = () => {
  return (
    <Card>
      <CardHeader>
        <Skeleton className="h-6 w-1/3 rounded-lg">
          <div className="h-6 bg-default-200"></div>
        </Skeleton>
      </CardHeader>
      <CardBody>
        <div className="flex flex-col gap-4">
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
  );
};
