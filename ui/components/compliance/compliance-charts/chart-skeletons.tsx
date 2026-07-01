import { Card, CardContent, CardHeader, Skeleton } from "@/components/shadcn";

export function RequirementsStatusCardSkeleton() {
  return (
    <Card
      variant="base"
      className="flex h-full min-h-[372px] flex-col justify-between xl:max-w-[400px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-[260px] rounded-xl" />
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        {/* Circular skeleton for donut chart */}
        <div className="mx-auto h-[172px] w-[172px]">
          <Skeleton className="size-[172px] rounded-full" />
        </div>

        {/* Bottom info box skeleton - inner card with horizontal items */}
        <Skeleton className="h-[97px] w-full shrink-0 rounded-xl" />
      </CardContent>
    </Card>
  );
}

export function TopFailedSectionsCardSkeleton() {
  return (
    <Card variant="base" className="flex h-full min-h-[372px] w-full flex-col">
      <CardHeader>
        <Skeleton className="h-6 w-48" />
      </CardHeader>
      <CardContent className="flex flex-1 flex-col justify-center gap-6">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex items-center gap-4">
            <Skeleton className="h-4 w-20" />
            <Skeleton className="h-[22px] flex-1" />
            <Skeleton className="h-4 w-24" />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export function SectionsFailureRateCardSkeleton() {
  return (
    <Card variant="base" className="flex min-h-[372px] min-w-[328px] flex-col">
      <CardHeader>
        <Skeleton className="h-6 w-48" />
      </CardHeader>
      <CardContent className="flex flex-1 items-center justify-center p-6">
        <div className="grid h-full w-full grid-cols-3 gap-2">
          {[...Array(9)].map((_, i) => (
            <Skeleton key={i} className="h-full w-full rounded" />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
