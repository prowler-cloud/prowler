import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

const SkeletonTableRow = () => {
  return (
    <tr className="border-border-neutral-secondary border-b last:border-b-0">
      {/* Notification dot */}
      <td className="px-3 py-4">
        <Skeleton className="size-2 rounded-full" />
      </td>
      {/* Status badge */}
      <td className="px-3 py-4">
        <Skeleton className="h-6 w-14 rounded-full" />
      </td>
      {/* Finding title */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-56 rounded" />
      </td>
      {/* Resource name */}
      <td className="px-3 py-4">
        <div className="flex items-center gap-2">
          <Skeleton className="size-4 rounded" />
          <Skeleton className="h-4 w-24 rounded" />
        </div>
      </td>
      {/* Severity badge */}
      <td className="px-3 py-4">
        <Skeleton className="h-6 w-16 rounded-full" />
      </td>
      {/* Provider icon */}
      <td className="px-3 py-4">
        <Skeleton className="size-8 rounded-md" />
      </td>
      {/* Service */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-16 rounded" />
      </td>
      {/* Region — flag + name */}
      <td className="px-3 py-4">
        <div className="flex items-center gap-1.5">
          <Skeleton className="size-4 rounded" />
          <Skeleton className="h-4 w-20 rounded" />
        </div>
      </td>
      {/* Time */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-24 rounded" />
      </td>
    </tr>
  );
};

export const SkeletonTableNewFindings = () => {
  const rows = 10;

  return (
    <div className="rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary flex w-full flex-col gap-4 overflow-hidden border p-4">
      {/* Header: title + description on the left, link on the right */}
      <div className="flex w-full items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <Skeleton className="h-5 w-64 rounded" />
          <Skeleton className="h-3 w-80 rounded" />
        </div>
        <Skeleton className="h-4 w-40 rounded" />
      </div>

      {/* Table */}
      <table className="w-full">
        <thead>
          <tr className="border-border-neutral-secondary border-b">
            {/* Notification header (no text) */}
            <th className="w-8 py-3" />
            {/* Status */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Finding */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-16 rounded" />
            </th>
            {/* Resource name */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-28 rounded" />
            </th>
            {/* Severity */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-16 rounded" />
            </th>
            {/* Provider */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-24 rounded" />
            </th>
            {/* Service */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Region */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Time */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, i) => (
            <SkeletonTableRow key={i} />
          ))}
        </tbody>
      </table>
    </div>
  );
};
