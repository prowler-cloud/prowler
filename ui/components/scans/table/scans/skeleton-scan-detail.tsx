export const SkeletonScanDetail = () => {
  return (
    <div className="flex flex-col gap-6 rounded-lg">
      {/* Header Skeleton */}
      <div className="flex items-center gap-4">
        <div className="bg-default-200 h-8 w-24 animate-pulse rounded-full" />
        <div className="flex items-center gap-2">
          <div className="bg-default-200 relative h-8 w-8 animate-pulse rounded-full" />
          <div className="flex flex-col gap-1">
            <div className="bg-default-200 h-4 w-32 animate-pulse rounded" />
            <div className="bg-default-200 h-3 w-24 animate-pulse rounded" />
          </div>
        </div>
      </div>

      {/* Scan Details Section Skeleton */}
      <div className="dark:bg-prowler-blue-400 flex flex-col gap-4 rounded-lg p-4 shadow">
        <div className="bg-default-200 h-5 w-32 animate-pulse rounded" />

        {/* First grid row */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={`grid1-${index}`} className="flex flex-col gap-2">
              <div className="bg-default-200 h-4 w-24 animate-pulse rounded" />
              <div className="bg-default-200 h-5 w-full animate-pulse rounded" />
            </div>
          ))}
        </div>

        {/* Second grid row */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={`grid2-${index}`} className="flex flex-col gap-2">
              <div className="bg-default-200 h-4 w-20 animate-pulse rounded" />
              <div className="bg-default-200 h-5 w-full animate-pulse rounded" />
            </div>
          ))}
        </div>

        {/* Scan ID field */}
        <div className="flex flex-col gap-2">
          <div className="bg-default-200 h-4 w-20 animate-pulse rounded" />
          <div className="bg-default-200 h-10 w-full animate-pulse rounded" />
        </div>

        {/* Third grid row */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <div key={`grid3-${index}`} className="flex flex-col gap-2">
              <div className="bg-default-200 h-4 w-24 animate-pulse rounded" />
              <div className="bg-default-200 h-5 w-full animate-pulse rounded" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
