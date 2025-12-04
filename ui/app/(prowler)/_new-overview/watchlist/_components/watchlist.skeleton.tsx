import { Card, CardContent, CardTitle } from "@/components/shadcn/card/card";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

export function WatchlistCardSkeleton() {
  return (
    <Card variant="base" className="flex min-h-[500px] min-w-[312px] flex-col">
      <CardTitle>
        <Skeleton className="h-7 w-[168px] rounded-xl" />
      </CardTitle>

      <CardContent className="flex flex-1 flex-col justify-center gap-8">
        {/* 6 skeleton rows */}
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} className="flex h-7 w-full items-start gap-6">
            <Skeleton className="h-7 w-[168px] rounded-xl" />
            <Skeleton className="h-7 flex-1 rounded-xl" />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
