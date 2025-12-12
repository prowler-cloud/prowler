import { Card, CardContent, CardTitle } from "@/components/shadcn";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

function ResourceCardSkeleton() {
  return (
    <div className="border-border-neutral-tertiary bg-bg-neutral-tertiary flex flex-1 flex-col gap-2 rounded-xl border px-3 py-2">
      {/* Header */}
      <div className="flex w-full items-center gap-1">
        <div className="flex flex-1 items-center gap-1">
          <Skeleton className="h-4 w-4" />
          <Skeleton className="h-5 w-16" />
        </div>
        <Skeleton className="h-3 w-16" />
      </div>
      {/* Content */}
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-1">
          <Skeleton className="h-5 w-12 rounded-full" />
          <Skeleton className="h-4 w-20" />
        </div>
        <div className="ml-6 flex flex-col gap-0.5">
          <div className="flex items-center gap-1">
            <Skeleton className="h-3 w-3" />
            <Skeleton className="h-4 w-12" />
          </div>
          <div className="flex items-center gap-1">
            <Skeleton className="h-3 w-3" />
            <Skeleton className="h-4 w-24" />
          </div>
        </div>
      </div>
    </div>
  );
}

export function ResourcesInventorySkeleton() {
  return (
    <Card variant="base" className="flex w-full flex-col">
      <div className="flex w-full items-center justify-between">
        <CardTitle>Resource Inventory</CardTitle>
        <Skeleton className="h-5 w-28" />
      </div>
      <CardContent className="mt-4 flex flex-col gap-3">
        {/* First row */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <ResourceCardSkeleton key={`row1-${i}`} />
          ))}
        </div>
        {/* Second row */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <ResourceCardSkeleton key={`row2-${i}`} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
