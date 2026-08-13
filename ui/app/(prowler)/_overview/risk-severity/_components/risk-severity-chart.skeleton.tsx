import { Card, CardContent, CardHeader, Skeleton } from "@/components/shadcn";

export function RiskSeverityChartSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] w-full min-w-0 flex-1 flex-col lg:w-auto lg:min-w-[485px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-[260px] rounded-xl" />
      </CardHeader>

      <CardContent className="flex flex-1 items-center justify-start px-6">
        <div className="flex w-full flex-col gap-6">
          {/* 5 horizontal bar skeletons */}
          {Array.from({ length: 5 }).map((_, index) => (
            <div key={index} className="flex h-7 w-full gap-6">
              <Skeleton className="h-full w-28 shrink-0 rounded-xl" />
              <Skeleton className="h-full flex-1 rounded-xl" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
