import { Skeleton } from "@/components/shadcn";

export function FindingSeverityOverTimeSkeleton() {
  return (
    <div role="status" aria-label="Loading severity trends">
      <div className="mb-8 w-fit">
        <div className="flex gap-2">
          {Array.from({ length: 3 }).map((_, index) => (
            <Skeleton key={index} className="h-10 w-12 rounded-full" />
          ))}
        </div>
      </div>
      <Skeleton className="h-[400px] w-full rounded-lg" />
    </div>
  );
}
