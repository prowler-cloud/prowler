import { Card, Skeleton } from "@/components/shadcn";

const SECTION_COUNT = 5;

/** Same layout as the configuration page, so nothing moves when it loads. */
export function ConfigurationSkeleton() {
  return (
    <div
      role="status"
      aria-label="Loading configuration"
      className="flex flex-col gap-6"
    >
      <Skeleton className="h-[68px] w-72" />
      <div className="flex flex-col-reverse gap-6 lg:grid lg:grid-cols-[minmax(0,1fr)_18rem] lg:items-start">
        <div className="flex flex-col gap-4">
          {Array.from({ length: SECTION_COUNT }, (_, index) => (
            <Card key={index} variant="base" padding="none">
              <div className="flex items-center gap-3 px-[18px] py-4">
                <Skeleton className="size-7 rounded-full" />
                <div className="flex flex-1 flex-col gap-1.5">
                  <Skeleton className="h-4 w-40" />
                  <Skeleton className="h-3 w-72" />
                </div>
                <Skeleton className="h-8 w-16" />
              </div>
            </Card>
          ))}
          <Skeleton className="h-36 w-full rounded-xl" />
        </div>
        <Skeleton className="h-[380px] w-full rounded-xl" />
      </div>
    </div>
  );
}
