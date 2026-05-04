import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

const SkeletonTableRow = () => {
  return (
    <tr className="border-border-neutral-secondary border-b">
      {/* Provider: logo + alias + UID */}
      <td className="w-[420px] px-3 py-4">
        <div className="flex items-center gap-3">
          <Skeleton className="size-9 rounded-lg" />
          <div className="space-y-1.5">
            <Skeleton className="h-4 w-32 rounded" />
            <Skeleton className="h-3 w-24 rounded" />
          </div>
        </div>
      </td>
      {/* Provider Groups: badge chips */}
      <td className="px-3 py-4">
        <div className="flex items-center gap-1.5">
          <Skeleton className="h-6 w-14 rounded-md" />
          <Skeleton className="h-6 w-16 rounded-md" />
        </div>
      </td>
      {/* Last Scan: date + time */}
      <td className="px-3 py-4">
        <div className="space-y-1">
          <Skeleton className="h-4 w-24 rounded" />
          <Skeleton className="h-3 w-16 rounded" />
        </div>
      </td>
      {/* Scan Schedule */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-12 rounded" />
      </td>
      {/* Status: icon + text */}
      <td className="px-3 py-4">
        <div className="flex items-center gap-2">
          <Skeleton className="size-4 rounded" />
          <Skeleton className="h-4 w-20 rounded" />
        </div>
      </td>
      {/* Added: date + time */}
      <td className="px-3 py-4">
        <div className="space-y-1">
          <Skeleton className="h-4 w-24 rounded" />
          <Skeleton className="h-3 w-16 rounded" />
        </div>
      </td>
      {/* Actions */}
      <td className="px-2 py-4">
        <Skeleton className="size-6 rounded" />
      </td>
    </tr>
  );
};

export const SkeletonTableProviders = () => {
  const rows = 10;

  return (
    <div className="rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary flex w-full flex-col gap-4 overflow-hidden border p-4">
      {/* Toolbar: Search + Total entries */}
      <div className="flex items-center justify-between">
        <Skeleton className="size-10 rounded-md" />
        <Skeleton className="h-4 w-28 rounded" />
      </div>

      {/* Table */}
      <table className="w-full">
        <thead>
          <tr className="border-border-neutral-secondary border-b">
            {/* Provider */}
            <th className="w-[420px] px-3 py-3 text-left">
              <Skeleton className="h-4 w-16 rounded" />
            </th>
            {/* Provider Groups */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-24 rounded" />
            </th>
            {/* Last Scan */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-16 rounded" />
            </th>
            {/* Scan Schedule */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-20 rounded" />
            </th>
            {/* Status */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
            {/* Added */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
            {/* Actions - empty header */}
            <th className="w-14 py-3" />
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, i) => (
            <SkeletonTableRow key={i} />
          ))}
        </tbody>
      </table>

      {/* Pagination */}
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
