import { cn } from "@/lib/utils";

interface SkeletonProps {
  className?: string;
  variant?: "default" | "card" | "table" | "text" | "circle" | "rectangular";
  width?: string | number;
  height?: string | number;
  animate?: boolean;
}

export function Skeleton({
  className,
  variant = "default",
  width,
  height,
  animate = true,
}: SkeletonProps) {
  const variantClasses = {
    default: "w-full h-4 rounded-lg",
    card: "w-full h-40 rounded-xl",
    table: "w-full h-60 rounded-lg",
    text: "w-24 h-4 rounded-full",
    circle: "rounded-full w-8 h-8",
    rectangular: "rounded-md",
  };

  return (
    <div
      style={{
        width: width
          ? typeof width === "number"
            ? `${width}px`
            : width
          : undefined,
        height: height
          ? typeof height === "number"
            ? `${height}px`
            : height
          : undefined,
      }}
      className={cn(
        "animate-pulse bg-gray-200 dark:bg-prowler-blue-800",
        variantClasses[variant],
        !animate && "animate-none",
        className,
      )}
    />
  );
}

export function SkeletonTable({
  rows = 5,
  columns = 4,
  className,
  roundedCells = true,
}: {
  rows?: number;
  columns?: number;
  className?: string;
  roundedCells?: boolean;
}) {
  return (
    <div className={cn("w-full space-y-4", className)}>
      {/* Header */}
      <div className="flex items-center space-x-4 pb-4">
        {Array.from({ length: columns }).map((_, index) => (
          <Skeleton
            key={`header-${index}`}
            className={cn("h-8", roundedCells && "rounded-lg")}
            width={`${100 / columns}%`}
            variant={roundedCells ? "default" : "rectangular"}
          />
        ))}
      </div>

      {/* Rows */}
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div
          key={`row-${rowIndex}`}
          className="flex items-center space-x-4 py-3"
        >
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton
              key={`cell-${rowIndex}-${colIndex}`}
              className={cn("h-6", roundedCells && "rounded-lg")}
              width={`${100 / columns}%`}
              variant={roundedCells ? "default" : "rectangular"}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonCard({ className }: { className?: string }) {
  return (
    <div className={cn("space-y-3", className)}>
      <Skeleton variant="card" />
      <Skeleton className="h-4 w-2/3" />
      <Skeleton className="h-4 w-1/2" />
    </div>
  );
}

export function SkeletonText({
  lines = 3,
  className,
  lastLineWidth = "w-1/2",
}: {
  lines?: number;
  className?: string;
  lastLineWidth?: string;
}) {
  return (
    <div className={cn("space-y-2", className)}>
      {Array.from({ length: lines - 1 }).map((_, index) => (
        <Skeleton key={index} className="h-4 w-full" variant="text" />
      ))}
      <Skeleton className={cn("h-4", lastLineWidth)} variant="text" />
    </div>
  );
}
