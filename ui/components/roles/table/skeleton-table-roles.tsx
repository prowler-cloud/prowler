import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

const SkeletonTableRow = () => {
  return (
    <tr className="border-border-neutral-secondary border-b last:border-b-0">
      {/* Role - bold name text */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-32 rounded" />
      </td>
      {/* Users - count text */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-16 rounded" />
      </td>
      {/* Invitations - count text */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-20 rounded" />
      </td>
      {/* Permissions - state text */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-20 rounded" />
      </td>
      {/* Added - date */}
      <td className="px-3 py-4">
        <Skeleton className="h-4 w-24 rounded" />
      </td>
      {/* Actions */}
      <td className="px-2 py-4">
        <Skeleton className="size-6 rounded" />
      </td>
    </tr>
  );
};

export const SkeletonTableRoles = () => {
  const rows = 10;

  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-secondary flex w-full flex-col gap-4 overflow-hidden rounded-[14px] border p-4 shadow-sm">
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
            {/* Role */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-12 rounded" />
            </th>
            {/* Users */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-14 rounded" />
            </th>
            {/* Invitations */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-20 rounded" />
            </th>
            {/* Permissions */}
            <th className="px-3 py-3 text-left">
              <Skeleton className="h-4 w-24 rounded" />
            </th>
            {/* Added */}
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
