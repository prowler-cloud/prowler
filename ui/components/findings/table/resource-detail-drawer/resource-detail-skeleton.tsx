import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

/**
 * Skeleton placeholder for the resource info grid in the detail drawer.
 * Mirrors the 4-column layout: EntityInfo × 2, InfoField × 2 per row,
 * plus the actions button.
 */
export function ResourceDetailSkeleton() {
  return (
    <div className="flex items-start gap-4">
      <div className="grid min-w-0 flex-1 grid-cols-1 gap-4 md:grid-cols-4 md:gap-x-8 md:gap-y-4">
        {/* Row 1: Account, Resource, Service, Region */}
        <EntityInfoSkeleton hasIcon />
        <EntityInfoSkeleton />
        <InfoFieldSkeleton labelWidth="w-12" valueWidth="w-20" />
        <InfoFieldSkeleton labelWidth="w-12" valueWidth="w-24" />

        {/* Row 2: Last detected, First seen, Failing for */}
        <InfoFieldSkeleton labelWidth="w-20" valueWidth="w-32" />
        <InfoFieldSkeleton labelWidth="w-16" valueWidth="w-32" />
        <InfoFieldSkeleton labelWidth="w-16" valueWidth="w-16" />
        <div className="hidden md:block" />

        {/* Row 3: Check ID, Finding ID, Finding UID */}
        <InfoFieldSkeleton labelWidth="w-14" valueWidth="w-36" />
        <InfoFieldSkeleton labelWidth="w-16" valueWidth="w-36" />
        <InfoFieldSkeleton labelWidth="w-20" valueWidth="w-36" />
      </div>

      {/* Actions button */}
      <Skeleton className="size-11 shrink-0 rounded-full" />
    </div>
  );
}

function EntityInfoSkeleton({ hasIcon = false }: { hasIcon?: boolean }) {
  return (
    <div className="flex items-center gap-4">
      {hasIcon && <Skeleton className="size-9 shrink-0 rounded-md" />}
      <div className="flex flex-col gap-0.5">
        <div className="flex items-center gap-1.5">
          <Skeleton className="size-4 rounded" />
          <Skeleton className="h-5 w-28 rounded" />
        </div>
        <Skeleton className="h-6 w-24 rounded-full" />
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
