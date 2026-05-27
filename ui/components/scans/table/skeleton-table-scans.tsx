import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { SCAN_JOBS_TAB, type ScanJobsTab } from "@/types";

const AccountCellSkeleton = () => (
  <td className="px-3 py-4">
    <div className="flex items-center gap-4">
      <Skeleton className="size-9 rounded-xl" />
      <div className="flex flex-col gap-1">
        <Skeleton className="h-3.5 w-20 rounded" />
        <div className="bg-bg-neutral-tertiary border-border-neutral-tertiary flex h-6 w-32 items-center gap-1 rounded-full border-2 px-2">
          <Skeleton className="h-3 w-20 rounded" />
          <Skeleton className="h-3.5 w-3.5 rounded" />
        </div>
      </div>
    </div>
  </td>
);

const ScanInfoCellSkeleton = () => (
  <td className="px-3 py-4">
    <div className="flex flex-col gap-1">
      <Skeleton className="h-3.5 w-32 rounded" />
      <div className="bg-bg-neutral-tertiary border-border-neutral-tertiary flex h-6 w-32 items-center gap-1 rounded-full border-2 px-2">
        <Skeleton className="h-3 w-20 rounded" />
        <Skeleton className="h-3.5 w-3.5 rounded" />
      </div>
    </div>
  </td>
);

const ProgressCellSkeleton = () => (
  <td className="px-3 py-4">
    <div className="flex min-w-[220px] items-center gap-3">
      <Skeleton className="h-2 w-[140px] rounded-full" />
      <Skeleton className="h-3.5 w-9 rounded" />
    </div>
  </td>
);

const ScheduleCellSkeleton = () => (
  <td className="px-3 py-4">
    <div className="flex flex-col gap-1">
      <Skeleton className="h-4 w-20 rounded" />
      <Skeleton className="h-3 w-32 rounded" />
    </div>
  </td>
);

const DateCellSkeleton = () => (
  <td className="px-3 py-4">
    <div className="flex flex-col gap-1">
      <Skeleton className="h-4 w-24 rounded" />
      <Skeleton className="h-3 w-20 rounded" />
    </div>
  </td>
);

const ResourcesCellSkeleton = () => (
  <td className="px-3 py-4">
    <Skeleton className="h-6 w-12 rounded" />
  </td>
);

const DurationCellSkeleton = () => (
  <td className="px-3 py-4">
    <Skeleton className="h-4 w-16 rounded" />
  </td>
);

const StatusCellSkeleton = () => (
  <td className="px-3 py-4">
    <Skeleton className="h-6 w-20 rounded-md" />
  </td>
);

const ActionsCellSkeleton = () => (
  <td className="px-2 py-4">
    <Skeleton className="size-7 rounded" />
  </td>
);

const HeaderLabel = ({ width }: { width: string }) => (
  <Skeleton className={`h-4 ${width} rounded`} />
);

interface ColumnDescriptor {
  headerWidth: string;
  Cell: () => React.JSX.Element;
}

const ACCOUNT_COLUMN: ColumnDescriptor = {
  headerWidth: "w-16",
  Cell: AccountCellSkeleton,
};
const SCAN_INFO_COLUMN: ColumnDescriptor = {
  headerWidth: "w-10",
  Cell: ScanInfoCellSkeleton,
};
const PROGRESS_COLUMN: ColumnDescriptor = {
  headerWidth: "w-16",
  Cell: ProgressCellSkeleton,
};
const SCHEDULE_COLUMN: ColumnDescriptor = {
  headerWidth: "w-16",
  Cell: ScheduleCellSkeleton,
};
const LAUNCHED_COLUMN: ColumnDescriptor = {
  headerWidth: "w-16",
  Cell: DateCellSkeleton,
};
const RESOURCES_COLUMN: ColumnDescriptor = {
  headerWidth: "w-20",
  Cell: ResourcesCellSkeleton,
};
const DURATION_COLUMN: ColumnDescriptor = {
  headerWidth: "w-16",
  Cell: DurationCellSkeleton,
};
const STATUS_COLUMN: ColumnDescriptor = {
  headerWidth: "w-12",
  Cell: StatusCellSkeleton,
};
const COMPLETED_COLUMN: ColumnDescriptor = {
  headerWidth: "w-20",
  Cell: DateCellSkeleton,
};
const NEXT_RUN_COLUMN: ColumnDescriptor = {
  headerWidth: "w-16",
  Cell: DateCellSkeleton,
};

const COLUMNS_BY_TAB: Record<ScanJobsTab, ColumnDescriptor[]> = {
  [SCAN_JOBS_TAB.ACTIVE]: [
    ACCOUNT_COLUMN,
    SCAN_INFO_COLUMN,
    PROGRESS_COLUMN,
    SCHEDULE_COLUMN,
    LAUNCHED_COLUMN,
  ],
  [SCAN_JOBS_TAB.COMPLETED]: [
    ACCOUNT_COLUMN,
    SCAN_INFO_COLUMN,
    RESOURCES_COLUMN,
    DURATION_COLUMN,
    STATUS_COLUMN,
    SCHEDULE_COLUMN,
    COMPLETED_COLUMN,
  ],
  [SCAN_JOBS_TAB.SCHEDULED]: [
    ACCOUNT_COLUMN,
    SCAN_INFO_COLUMN,
    SCHEDULE_COLUMN,
    NEXT_RUN_COLUMN,
  ],
};

interface SkeletonTableScansProps {
  tab?: ScanJobsTab;
  rows?: number;
}

export const SkeletonTableScans = ({
  tab = SCAN_JOBS_TAB.ACTIVE,
  rows = 6,
}: SkeletonTableScansProps = {}) => {
  const columns = COLUMNS_BY_TAB[tab];

  return (
    <div className="rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary flex w-full flex-col gap-4 overflow-hidden border p-4">
      {/* Toolbar: only total entries on the right (scans table has no search) */}
      <div className="flex items-center justify-end">
        <Skeleton className="h-4 w-28 rounded" />
      </div>

      {/* Table */}
      <table className="w-full">
        <thead>
          <tr className="border-border-neutral-secondary border-b">
            {columns.map((column, i) => (
              <th key={i} className="px-3 py-3 text-left">
                <HeaderLabel width={column.headerWidth} />
              </th>
            ))}
            {/* Actions - empty header */}
            <th className="w-10 py-3" />
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, rowIdx) => (
            <tr
              key={rowIdx}
              className="border-border-neutral-secondary border-b last:border-b-0"
            >
              {columns.map(({ Cell }, colIdx) => (
                <Cell key={colIdx} />
              ))}
              <ActionsCellSkeleton />
            </tr>
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
