import React from "react";

export const SkeletonFindingSummary = () => {
  return (
    <div className="dark:bg-prowler-blue-400 flex animate-pulse flex-col gap-4 rounded-lg p-4 shadow">
      <div className="flex items-center justify-between gap-4">
        <div className="bg-default-200 h-5 w-1/3 rounded" />
        <div className="flex items-center gap-2">
          <div className="bg-default-200 h-5 w-16 rounded" />
          <div className="bg-default-200 h-5 w-16 rounded" />
          <div className="bg-default-200 h-5 w-5 rounded-full" />
        </div>
      </div>
    </div>
  );
};
