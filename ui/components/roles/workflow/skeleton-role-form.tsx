import { Card, Skeleton } from "@/components/shadcn";

export const SkeletonRoleForm = () => {
  return (
    <Card className="flex h-full w-full flex-col gap-5 rounded-lg p-4">
      {/* Table headers */}
      <div className="hidden justify-between md:flex">
        <Skeleton className="h-8 w-1/12 rounded-lg" />
        <Skeleton className="h-8 w-2/12 rounded-lg" />
        <Skeleton className="h-8 w-2/12 rounded-lg" />
        <Skeleton className="h-8 w-2/12 rounded-lg" />
        <Skeleton className="h-8 w-2/12 rounded-lg" />
        <Skeleton className="h-8 w-1/12 rounded-lg" />
        <Skeleton className="h-8 w-1/12 rounded-lg" />
      </div>

      {/* Table body */}
      <div className="flex flex-col gap-3">
        {[...Array(3)].map((_, index) => (
          <div
            key={index}
            className="flex flex-col items-center justify-between md:flex-row md:gap-4"
          >
            <Skeleton className="mb-2 h-12 w-full rounded-lg md:mb-0 md:w-1/12" />
            <Skeleton className="mb-2 h-12 w-full rounded-lg md:mb-0 md:w-2/12" />
            <Skeleton className="mb-2 hidden h-12 rounded-lg sm:flex md:mb-0 md:w-2/12" />
            <Skeleton className="mb-2 hidden h-12 rounded-lg sm:flex md:mb-0 md:w-2/12" />
            <Skeleton className="mb-2 hidden h-12 rounded-lg sm:flex md:mb-0 md:w-2/12" />
            <Skeleton className="mb-2 hidden h-12 rounded-lg sm:flex md:mb-0 md:w-1/12" />
            <Skeleton className="mb-2 hidden h-12 rounded-lg sm:flex md:mb-0 md:w-1/12" />
          </div>
        ))}
      </div>
    </Card>
  );
};
