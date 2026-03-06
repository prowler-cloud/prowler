import { Card, CardContent, CardHeader, Skeleton } from "@/components/shadcn";

export function StatusChartSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[312px] flex-1 flex-col justify-between md:min-w-[380px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-[260px] rounded-xl" />
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        {/* Circular skeleton for donut chart */}
        <div className="mx-auto h-[172px] w-[172px]">
          <Skeleton className="size-[172px] rounded-full" />
        </div>

        {/* Bottom info box skeleton */}
        <Skeleton className="h-[97px] w-full shrink-0 rounded-xl" />
      </CardContent>
    </Card>
  );
}
