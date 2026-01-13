import { Card, CardContent, CardHeader, Skeleton } from "@/components/shadcn";

export function ThreatScoreSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] w-full flex-col justify-between lg:max-w-[312px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-36 rounded-xl" />
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        {/* Circular skeleton for radial chart */}
        <div className="relative mx-auto h-[172px] w-full max-w-[250px]">
          <Skeleton className="mx-auto size-[170px] rounded-full" />
        </div>

        {/* Bottom info box skeleton */}
        <Skeleton className="h-[97px] w-full shrink-0 rounded-xl" />
      </CardContent>
    </Card>
  );
}
