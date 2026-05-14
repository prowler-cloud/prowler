import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

const SkeletonTableRow = () => {
  return (
    <tr className="border-border-neutral-secondary border-b last:border-b-0">
      {/* Name - clickable text with copy icon */}
      <td className="px-3 py-4">
        <div className="flex items-center gap-2">
          <Skeleton className="h-4 w-32 rounded" />
          <Skeleton className="size-4 rounded" />
        </div>
      </td>
      {/* Provider Account - logo + alias + uid chip */}
      <td className="px-3 py-4">
        <div className="flex items-center gap-2">
          <Skeleton className="size-9 rounded-xl" />
          <div className="flex flex-col gap-1">
            <Skeleton className="h-3.5 w-20 rounded" />
            <div className="bg-bg-neutral-tertiary flex h-6 w-24 items-center gap-1 rounded-xl px-1.5">
              <Skeleton className="h-3 w-16 rounded" />
              <Skeleton className="size-3.5 rounded" />
            </div>
          </div>
        </div>
      </td>
      {/* Failed Findings - badge */}
      <td className="px-3 py-4">
        <Skeleton className="h-6 w-10 rounded-full" />
      </td>
      {/* Group */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-20 rounded" />
      </td>
      {/* Type */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-24 rounded" />
      </td>
      {/* Region */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-20 rounded" />
      </td>
      {/* Service */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-16 rounded" />
      </td>
      {/* Actions */}
      <td className="px-2 py-4">
        <Skeleton className="size-6 rounded" />
      </td>
    </tr>
  );
};

export const SkeletonTableResources = () => {
  const rows = 10;

  return (
    <div className="rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary flex w-full flex-col gap-4 overflow-hidden border p-4">
      {/* Toolbar: Search + Total entries */}
      <div className="flex items-center justify-between">
        {/* Search icon button */}
        <Skeleton className="size-10 rounded-md" />
        {/* Total entries */}
        <Skeleton className="h-4 w-28 rounded" />
      </div>

      {/* Table */}
      <table className="w-full">
        <thead>
          <tr className="border-border-neutral-secondary border-b">
            {/* Name */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
            {/* Provider Account */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-28 rounded" />
            </th>
            {/* Failed Findings */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-24 rounded" />
            </th>
            {/* Group */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
            {/* Type */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-10 rounded" />
            </th>
            {/* Region */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Service */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Actions - empty header */}
            <th className="w-10 py-3" />
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
        {/* Rows per page */}
        <div className="flex items-center gap-2">
          <Skeleton className="h-4 w-24 rounded" />
          <Skeleton className="h-9 w-16 rounded-md" />
        </div>
        {/* Page info + navigation */}
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
