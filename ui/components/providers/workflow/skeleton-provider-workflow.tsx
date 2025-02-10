import { Card, CardBody, CardHeader, Skeleton } from "@nextui-org/react";

export const SkeletonProviderWorkflow = () => {
  return (
    <Card>
      <CardHeader className="flex flex-col items-start space-y-2">
        <Skeleton className="h-6 w-2/3 rounded-lg">
          <div className="h-6 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="h-4 w-1/2 rounded-lg">
          <div className="h-4 bg-default-200"></div>
        </Skeleton>
      </CardHeader>
      <CardBody className="flex flex-col items-start space-y-6">
        <div className="flex space-x-4">
          <Skeleton className="h-12 w-12 rounded-lg">
            <div className="h-12 w-12 bg-default-200"></div>
          </Skeleton>
          <Skeleton className="h-12 w-12 rounded-lg">
            <div className="h-12 w-12 bg-default-200"></div>
          </Skeleton>
        </div>
        <Skeleton className="h-5 w-3/4 rounded-lg">
          <div className="h-5 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="h-12 w-40 self-end rounded-lg">
          <div className="h-12 bg-default-200"></div>
        </Skeleton>
      </CardBody>
    </Card>
  );
};
