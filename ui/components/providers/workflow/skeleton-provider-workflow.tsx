import { Card, CardBody, CardHeader } from "@heroui/card";
import { Skeleton } from "@heroui/skeleton";

export const SkeletonProviderWorkflow = () => {
  return (
    <Card>
      <CardHeader className="flex flex-col items-start gap-2">
        <Skeleton className="h-6 w-2/3 rounded-lg">
          <div className="bg-default-200 h-6"></div>
        </Skeleton>
        <Skeleton className="h-4 w-1/2 rounded-lg">
          <div className="bg-default-200 h-4"></div>
        </Skeleton>
      </CardHeader>
      <CardBody className="flex flex-col items-start gap-6">
        <div className="flex gap-4">
          <Skeleton className="h-12 w-12 rounded-lg">
            <div className="bg-default-200 h-12 w-12"></div>
          </Skeleton>
          <Skeleton className="h-12 w-12 rounded-lg">
            <div className="bg-default-200 h-12 w-12"></div>
          </Skeleton>
        </div>
        <Skeleton className="h-5 w-3/4 rounded-lg">
          <div className="bg-default-200 h-5"></div>
        </Skeleton>
        <Skeleton className="h-12 w-40 self-end rounded-lg">
          <div className="bg-default-200 h-12"></div>
        </Skeleton>
      </CardBody>
    </Card>
  );
};
