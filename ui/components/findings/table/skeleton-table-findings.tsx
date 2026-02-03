import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

const SkeletonTableRow = () => {
  return (
    <tr className="border-border-neutral-secondary border-b">
      {/* Notification dot */}
      <td className="py-4 pr-2">
        <div className="flex h-full items-center">
          <Skeleton className="size-1.5 rounded-full" />
        </div>
      </td>
      {/* Checkbox */}
      <td className="px-2 py-4">
        <div className="bg-bg-input-primary border-border-input-primary size-6 rounded-sm border shadow-[0_1px_2px_0_rgba(0,0,0,0.1)]" />
      </td>
      {/* Status */}
      <td className="px-3 py-4">
        <Skeleton className="h-6 w-11 rounded-md" />
      </td>
      {/* Finding - multiline text */}
      <td className="w-[300px] px-3 py-4">
        <div className="space-y-1.5">
          <Skeleton className="h-4 w-full rounded" />
          <Skeleton className="h-4 w-4/5 rounded" />
        </div>
      </td>
      {/* Resource name chip */}
      <td className="px-3 py-4">
        <div className="bg-bg-neutral-tertiary flex h-8 w-28 items-center gap-2 rounded-lg px-2">
          <Skeleton className="size-4 rounded" />
          <Skeleton className="h-3.5 w-16 rounded" />
          <Skeleton className="ml-auto size-3.5 rounded" />
        </div>
      </td>
      {/* Severity */}
      <td className="px-3 py-4">
        <div className="flex items-center gap-2">
          <Skeleton className="size-2 rounded-full" />
          <Skeleton className="h-4 w-12 rounded" />
        </div>
      </td>
      {/* Provider icon */}
      <td className="px-3 py-4">
        <Skeleton className="size-9 rounded-lg" />
      </td>
      {/* Service */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-20 rounded" />
      </td>
      {/* Time */}
      <td className="px-3 py-4">
        <div className="space-y-1">
          <Skeleton className="h-4 w-24 rounded" />
          <Skeleton className="h-3 w-20 rounded" />
        </div>
      </td>
      {/* Actions */}
      <td className="px-2 py-4">
        <Skeleton className="size-6 rounded" />
      </td>
    </tr>
  );
};

export const SkeletonTableFindings = () => {
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
            {/* Notification - empty header */}
            <th className="w-6 py-3" />
            {/* Checkbox */}
            <th className="w-10 px-2 py-3">
              <div className="bg-bg-input-primary border-border-input-primary size-6 rounded-sm border shadow-[0_1px_2px_0_rgba(0,0,0,0.1)]" />
            </th>
            {/* Status */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
            {/* Finding */}
            <th className="w-[300px] px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Resource name */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-24 rounded" />
            </th>
            {/* Severity */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Provider */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Service */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
            {/* Time */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-10 rounded" />
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
