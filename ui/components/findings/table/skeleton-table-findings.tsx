import { Card, Skeleton } from "@nextui-org/react";
import React from "react";

export const SkeletonTableFindings = () => {
  return (
    <Card className="h-full w-full space-y-5 p-4" radius="sm">
      {/* Table headers */}
      <div className="hidden justify-between md:flex">
        <Skeleton className="w-1/12 rounded-lg">
          <div className="h-8 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="w-2/12 rounded-lg">
          <div className="h-8 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="w-2/12 rounded-lg">
          <div className="h-8 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="w-2/12 rounded-lg">
          <div className="h-8 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="w-2/12 rounded-lg">
          <div className="h-8 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="w-1/12 rounded-lg">
          <div className="h-8 bg-default-200"></div>
        </Skeleton>
        <Skeleton className="w-1/12 rounded-lg">
          <div className="h-8 bg-default-200"></div>
        </Skeleton>
      </div>

      {/* Table body */}
      <div className="space-y-3">
        {[...Array(3)].map((_, index) => (
          <div
            key={index}
            className="flex flex-col items-center justify-between space-x-0 md:flex-row md:space-x-4"
          >
            <Skeleton className="mb-2 w-full rounded-lg md:mb-0 md:w-1/12">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="mb-2 w-full rounded-lg md:mb-0 md:w-2/12">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-2/12">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-2/12">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-2/12">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-1/12">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-1/12">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
          </div>
        ))}
      </div>
    </Card>
  );
};
