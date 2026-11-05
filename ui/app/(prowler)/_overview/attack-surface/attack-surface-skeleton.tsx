import { Card, CardContent, Skeleton } from "@/components/shadcn";

export function AttackSurfaceSkeleton() {
  return (
    <Card
      variant="base"
      className="flex w-full flex-col"
      role="status"
      aria-label="Loading attack surface data"
    >
      <Skeleton className="h-7 w-32 rounded-xl" />
      <CardContent className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Card
            key={index}
            variant="inner"
            padding="md"
            className="flex min-h-[120px] flex-col justify-between"
            aria-hidden="true"
          >
            <div className="flex flex-col gap-2">
              <Skeleton className="h-12 w-20 rounded-xl" />
              <Skeleton className="h-5 w-40 max-w-full rounded-xl" />
            </div>
          </Card>
        ))}
      </CardContent>
    </Card>
  );
}
