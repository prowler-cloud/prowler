import { FILTER_CONTROL_COLUMN_CLASS } from "@/components/findings/findings-filters.utils";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

const FILTER_CONTROL_PLACEHOLDERS = 5;

export const FindingsFiltersSkeleton = () => {
  return (
    <div className="flex flex-wrap items-center gap-3">
      {Array.from({ length: FILTER_CONTROL_PLACEHOLDERS }, (_, index) => (
        <Skeleton
          key={index}
          className={`h-[52px] rounded-lg ${FILTER_CONTROL_COLUMN_CLASS}`}
        />
      ))}
    </div>
  );
};
