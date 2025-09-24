import { Card, CardBody, Skeleton } from "@nextui-org/react";

export const SkeletonUserInfo = () => {
  return (
    <div className="space-y-6">
      {/* User Information */}
      <Card>
        <CardBody>
          <div className="space-y-3">
            {/* Name */}
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-default-600">Name:</p>
              <Skeleton className="h-5 w-24 rounded-lg">
                <div className="h-5 w-24 bg-default-200"></div>
              </Skeleton>
            </div>
            {/* Email */}
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-default-600">Email:</p>
              <Skeleton className="h-5 w-32 rounded-lg">
                <div className="h-5 w-32 bg-default-200"></div>
              </Skeleton>
            </div>
            {/* Company */}
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-default-600">Company:</p>
              <Skeleton className="h-5 w-28 rounded-lg">
                <div className="h-5 w-28 bg-default-200"></div>
              </Skeleton>
            </div>
            {/* Date Joined */}
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-default-600">
                Date Joined:
              </p>
              <Skeleton className="h-5 w-36 rounded-lg">
                <div className="h-5 w-36 bg-default-200"></div>
              </Skeleton>
            </div>
            {/* Tenant ID */}
            <div className="flex items-center justify-between">
              <p className="text-sm font-semibold text-default-600">
                Tenant ID:
              </p>
              <Skeleton className="h-5 w-32 rounded-lg">
                <div className="h-5 w-32 bg-default-200"></div>
              </Skeleton>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* Roles */}
      <Card>
        <CardBody>
          <h4 className="mb-3 text-sm font-semibold">Roles</h4>
          <div className="flex flex-wrap gap-2">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-6 w-20 rounded-full">
                <div className="h-6 w-20 rounded-full bg-default-200"></div>
              </Skeleton>
            ))}
          </div>
        </CardBody>
      </Card>

      {/* Memberships */}
      <Card>
        <CardBody>
          <h4 className="mb-3 text-sm font-semibold">Memberships</h4>
          <div className="space-y-2">
            {[1, 2].map((i) => (
              <Skeleton key={i} className="h-16 w-full rounded-md">
                <div className="h-16 w-full rounded-md bg-default-200"></div>
              </Skeleton>
            ))}
          </div>
        </CardBody>
      </Card>
    </div>
  );
};
