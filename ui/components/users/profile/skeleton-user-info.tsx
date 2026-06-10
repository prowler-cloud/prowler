import { Card, CardContent, Skeleton } from "@/components/shadcn";

export const SkeletonUserInfo = () => {
  return (
    <div className="flex flex-col gap-6">
      {/* User Information */}
      <Card>
        <CardContent className="p-3">
          <div className="flex flex-col gap-3">
            {/* Name */}
            <div className="flex items-center justify-between">
              <p className="text-default-600 text-sm font-semibold">Name:</p>
              <Skeleton className="h-5 w-24 rounded-lg" />
            </div>
            {/* Email */}
            <div className="flex items-center justify-between">
              <p className="text-default-600 text-sm font-semibold">Email:</p>
              <Skeleton className="h-5 w-32 rounded-lg" />
            </div>
            {/* Company */}
            <div className="flex items-center justify-between">
              <p className="text-default-600 text-sm font-semibold">Company:</p>
              <Skeleton className="h-5 w-28 rounded-lg" />
            </div>
            {/* Date Joined */}
            <div className="flex items-center justify-between">
              <p className="text-default-600 text-sm font-semibold">
                Date Joined:
              </p>
              <Skeleton className="h-5 w-36 rounded-lg" />
            </div>
            {/* Tenant ID */}
            <div className="flex items-center justify-between">
              <p className="text-default-600 text-sm font-semibold">
                Tenant ID:
              </p>
              <Skeleton className="h-5 w-32 rounded-lg" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Roles */}
      <Card>
        <CardContent className="p-3">
          <h4 className="mb-3 text-sm font-semibold">Roles</h4>
          <div className="flex flex-wrap gap-2">
            {[1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-6 w-20 rounded-full" />
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Memberships */}
      <Card>
        <CardContent className="p-3">
          <h4 className="mb-3 text-sm font-semibold">Memberships</h4>
          <div className="flex flex-col gap-2">
            {[1, 2].map((i) => (
              <Skeleton key={i} className="h-16 w-full rounded-md" />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
