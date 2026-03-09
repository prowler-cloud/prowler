import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

export const SkeletonTableProviders = () => {
  return (
    <div className="rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary flex w-full flex-col gap-4 overflow-hidden border p-4">
      <div className="flex items-center justify-between">
        <Skeleton className="h-10 w-56 rounded-md" />
        <Skeleton className="h-4 w-28 rounded" />
      </div>

      <div className="grid grid-cols-[2fr_1fr_1fr_1fr_40px] gap-3 border-b pb-3">
        <Skeleton className="h-4 w-20 rounded" />
        <Skeleton className="h-4 w-24 rounded" />
        <Skeleton className="h-4 w-16 rounded" />
        <Skeleton className="h-4 w-12 rounded" />
        <Skeleton className="h-4 w-4 rounded" />
      </div>

      <div className="flex flex-col gap-3">
        {Array.from({ length: 8 }).map((_, index) => (
          <div
            key={index}
            className="grid grid-cols-[2fr_1fr_1fr_1fr_40px] gap-3"
          >
            <Skeleton className="h-14 rounded-xl" />
            <Skeleton className="h-14 rounded-xl" />
            <Skeleton className="h-14 rounded-xl" />
            <Skeleton className="h-14 rounded-xl" />
            <Skeleton className="h-14 rounded-xl" />
          </div>
        ))}
      </div>

      <div className="flex items-center justify-between pt-2">
        <div className="flex items-center gap-2">
          <Skeleton className="h-4 w-24 rounded" />
          <Skeleton className="h-9 w-16 rounded-md" />
        </div>
        <div className="flex items-center gap-4">
          <Skeleton className="h-4 w-24 rounded" />
          <div className="flex gap-1">
            <Skeleton className="size-9 rounded-md" />
            <Skeleton className="size-9 rounded-md" />
            <Skeleton className="size-9 rounded-md" />
            <Skeleton className="size-9 rounded-md" />
          </div>
        </div>
      </div>
    </div>
  );
};
