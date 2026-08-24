import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

/**
 * Skeleton placeholder for the resource info grid in the detail drawer.
 * Mirrors the drawer layout so added metadata fields don't leave visual gaps
 * while the next resource is loading.
 */
export function ResourceDetailSkeleton() {
  return (
    <>
      <div className="flex items-start gap-4" aria-hidden="true">
        <div
          data-responsive-container
          className="@container flex min-w-0 flex-1 flex-col gap-4"
        >
          {/* Row 1: Provider, Resource, Service, Region */}
          <div className="grid min-w-0 grid-cols-2 gap-4 @md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,0.55fr)_minmax(0,0.7fr)] @md:gap-x-8">
            <div className="col-span-2 @md:col-span-1">
              <EntityInfoSkeleton hasIcon labelWidth="w-12" />
            </div>
            <div className="col-span-2 @md:col-span-1">
              <EntityInfoSkeleton labelWidth="w-14" />
            </div>
            <InfoFieldSkeleton labelWidth="w-12" valueWidth="w-20" />
            <InfoFieldSkeleton labelWidth="w-12" valueWidth="w-24" />
          </div>

          {/* Row 2: Last detected, First seen, Failing for */}
          <div className="grid min-w-0 grid-cols-2 gap-4 @md:grid-cols-3 @md:gap-x-8">
            <InfoFieldSkeleton labelWidth="w-20" valueWidth="w-32" />
            <InfoFieldSkeleton labelWidth="w-16" valueWidth="w-32" />
            <InfoFieldSkeleton labelWidth="w-16" valueWidth="w-16" />
          </div>
        </div>

        {/* Actions ⋮ — same footprint as the bordered ActionDropdown trigger */}
        <Skeleton className="size-8 shrink-0 rounded-md" />
      </div>

      {/* Status line card (status_extended) below the resource info */}
      <div
        className="border-border-neutral-secondary flex flex-col gap-2 rounded-lg border p-4"
        aria-hidden="true"
      >
        <Skeleton className="h-4 w-full rounded" />
        <Skeleton className="h-4 w-2/3 rounded" />
      </div>
    </>
  );
}

function EntityInfoSkeleton({
  hasIcon = false,
  labelWidth,
}: {
  hasIcon?: boolean;
  labelWidth?: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      {labelWidth && <Skeleton className={`h-3 ${labelWidth} rounded`} />}
      <div className="flex items-center gap-4">
        {hasIcon && <Skeleton className="size-9 shrink-0 rounded-md" />}
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-1.5">
            <Skeleton className="size-4 rounded" />
            <Skeleton className="h-5 w-28 rounded" />
          </div>
          {/* "UID:" label + code-snippet pill */}
          <div className="flex items-center gap-2">
            <Skeleton className="h-3.5 w-7 rounded" />
            <Skeleton className="h-6 w-28 rounded-md" />
          </div>
        </div>
      </div>
    </div>
  );
}

function InfoFieldSkeleton({
  labelWidth,
  valueWidth,
}: {
  labelWidth: string;
  valueWidth: string;
}) {
  return (
    <div className="flex flex-col gap-1">
      <Skeleton className={`h-3.5 ${labelWidth} rounded`} />
      <Skeleton className={`h-5 ${valueWidth} rounded`} />
    </div>
  );
}
