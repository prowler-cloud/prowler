import { Skeleton } from "@/components/shadcn";

interface SkeletonAccordionProps {
  itemCount?: number;
  className?: string;
  isCompact?: boolean;
}

export const SkeletonAccordion = ({
  itemCount = 3,
  className = "",
  isCompact = false,
}: SkeletonAccordionProps) => {
  const itemHeight = isCompact ? "h-10" : "h-14";

  return (
    <div
      className={`flex w-full flex-col gap-2 ${className} rounded-xl border border-gray-300 p-2 dark:border-gray-700`}
    >
      {[...Array(itemCount)].map((_, index) => (
        <Skeleton key={index} className={`${itemHeight} rounded-lg`} />
      ))}
    </div>
  );
};

SkeletonAccordion.displayName = "SkeletonAccordion";
