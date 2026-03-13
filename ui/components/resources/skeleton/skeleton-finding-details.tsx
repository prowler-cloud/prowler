import React from "react";

export const SkeletonFindingDetails = () => {
  return (
    <div className="dark:bg-prowler-blue-400 flex animate-pulse flex-col gap-6 rounded-lg p-4 shadow">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="bg-default-200 h-6 w-2/3 rounded" />
        <div className="flex items-center gap-x-4">
          <div className="bg-default-200 h-5 w-6 rounded-full" />
          <div className="bg-default-200 h-6 w-20 rounded" />
        </div>
      </div>

      {/* Metadata Section */}
      <div className="flex flex-wrap gap-4">
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} className="flex flex-col gap-1">
            <div className="bg-default-200 h-4 w-20 rounded" />
            <div className="bg-default-200 h-5 w-40 rounded" />
          </div>
        ))}
      </div>

      {/* InfoField Blocks */}
      {Array.from({ length: 3 }).map((_, index) => (
        <div key={index} className="flex flex-col gap-2">
          <div className="bg-default-200 h-4 w-28 rounded" />
          <div className="bg-default-200 h-5 w-full rounded" />
        </div>
      ))}

      {/* Risk and Description Sections */}
      <div className="flex flex-col gap-2">
        <div className="bg-default-200 h-4 w-28 rounded" />
        <div className="bg-default-200 h-16 w-full rounded" />
      </div>

      <div className="bg-default-200 h-4 w-36 rounded" />

      <div className="flex flex-col gap-2">
        <div className="bg-default-200 h-4 w-24 rounded" />
        <div className="bg-default-200 h-5 w-2/3 rounded" />
        <div className="bg-default-200 h-4 w-24 rounded" />
      </div>

      <div className="flex flex-col gap-2">
        <div className="bg-default-200 h-4 w-28 rounded" />
        <div className="bg-default-200 h-10 w-full rounded" />
      </div>

      {/* Additional Resources */}
      <div className="flex flex-col gap-2">
        <div className="bg-default-200 h-4 w-36 rounded" />
        <div className="bg-default-200 h-5 w-32 rounded" />
      </div>

      {/* Categories */}
      <div className="flex flex-col gap-2">
        <div className="bg-default-200 h-4 w-24 rounded" />
        <div className="bg-default-200 h-5 w-1/3 rounded" />
      </div>

      {/* Provider Info Section */}
      <div className="mt-4 flex items-center gap-2">
        <div className="bg-default-200 relative h-8 w-8 rounded-full">
          <div className="bg-default-300 absolute top-0 right-0 h-2 w-2 rounded-full" />
        </div>
        <div className="flex max-w-[120px] flex-col gap-1">
          <div className="bg-default-200 h-4 w-full rounded" />
          <div className="bg-default-200 h-4 w-16 rounded" />
        </div>
      </div>
    </div>
  );
};
