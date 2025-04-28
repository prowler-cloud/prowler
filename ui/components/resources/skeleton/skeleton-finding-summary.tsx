import React from "react";

export const SkeletonFindingSummary = () => {
    return (<div className="flex animate-pulse flex-col gap-4 rounded-lg p-4 shadow dark:bg-prowler-blue-400">
        <div className="flex items-center justify-between gap-4">
            <div className="h-5 w-1/3 rounded bg-default-200" />
            <div className="flex items-center gap-2">
                <div className="h-5 w-16 rounded bg-default-200" />
                <div className="h-5 w-16 rounded bg-default-200" />
                <div className="h-5 w-5 rounded-full bg-default-200" />
            </div>
        </div>
    </div>);
}