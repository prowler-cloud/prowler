import React from "react";

export const SkeletonFindingDetails = () => {
  return (
    <div className="flex animate-pulse flex-col gap-6 rounded-lg p-4 shadow dark:bg-prowler-blue-400">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="h-6 w-2/3 rounded bg-default-200" />
        <div className="flex items-center gap-x-4">
          <div className="h-5 w-6 rounded-full bg-default-200" />
          <div className="h-6 w-20 rounded bg-default-200" />
        </div>
      </div>

      {/* Metadata Section */}
      <div className="flex flex-wrap gap-4">
        {Array.from({ length: 6 }).map((_, index) => (
          <div key={index} className="flex flex-col gap-1">
            <div className="h-4 w-20 rounded bg-default-200" />
            <div className="h-5 w-40 rounded bg-default-200" />
          </div>
        ))}
      </div>

      {/* InfoField Blocks */}
      {Array.from({ length: 3 }).map((_, index) => (
        <div key={index} className="flex flex-col gap-2">
          <div className="h-4 w-28 rounded bg-default-200" />
          <div className="h-5 w-full rounded bg-default-200" />
        </div>
      ))}

      {/* Risk and Description Sections */}
      <div className="flex flex-col gap-2">
        <div className="h-4 w-28 rounded bg-default-200" />
        <div className="h-16 w-full rounded bg-default-200" />
      </div>

      <div className="h-4 w-36 rounded bg-default-200" />

      <div className="flex flex-col gap-2">
        <div className="h-4 w-24 rounded bg-default-200" />
        <div className="h-5 w-2/3 rounded bg-default-200" />
        <div className="h-4 w-24 rounded bg-default-200" />
      </div>

      <div className="flex flex-col gap-2">
        <div className="h-4 w-28 rounded bg-default-200" />
        <div className="h-10 w-full rounded bg-default-200" />
      </div>

      {/* Additional Resources */}
      <div className="flex flex-col gap-2">
        <div className="h-4 w-36 rounded bg-default-200" />
        <div className="h-5 w-32 rounded bg-default-200" />
      </div>

      {/* Categories */}
      <div className="flex flex-col gap-2">
        <div className="h-4 w-24 rounded bg-default-200" />
        <div className="h-5 w-1/3 rounded bg-default-200" />
      </div>

      {/* Provider Info Section */}
      <div className="mt-4 flex items-center gap-2">
        <div className="relative h-8 w-8 rounded-full bg-default-200">
          <div className="absolute right-0 top-0 h-2 w-2 rounded-full bg-default-300" />
        </div>
        <div className="flex max-w-[120px] flex-col gap-1">
          <div className="h-4 w-full rounded bg-default-200" />
          <div className="h-4 w-16 rounded bg-default-200" />
        </div>
      </div>
    </div>
  );
};
