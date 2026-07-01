import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

export function RiskPipelineViewSkeleton() {
  return (
    <div className="border-border-neutral-primary bg-bg-neutral-secondary flex h-[460px] w-full flex-col space-y-4 rounded-lg border p-4">
      <Skeleton className="h-6 w-1/4 rounded" />
      <div className="flex flex-1 items-center justify-center">
        <Skeleton className="h-[380px] w-full rounded" />
      </div>
    </div>
  );
}
