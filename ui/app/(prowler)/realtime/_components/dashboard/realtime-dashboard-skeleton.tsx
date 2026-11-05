import { OverviewTabSkeleton } from "@/app/(prowler)/realtime/_components/overview/overview-tab";
import { Card, CardContent, Skeleton } from "@/components/shadcn";

/** Same blocks as the dashboard: header card, tab row, overview. */
export function RealtimeDashboardSkeleton() {
  return (
    <div className="flex flex-col gap-6" aria-busy="true">
      <Card variant="base" padding="lg">
        <CardContent className="flex flex-wrap items-end gap-6">
          <Skeleton className="h-[62px] w-72" />
          <Skeleton className="h-[46px] w-24" />
          <Skeleton className="h-[46px] w-40" />
          <Skeleton className="h-[46px] w-56" />
        </CardContent>
      </Card>
      <Skeleton className="h-10 w-full max-w-3xl" />
      <OverviewTabSkeleton />
    </div>
  );
}
