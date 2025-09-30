import { Card } from "@heroui/card";
import { Skeleton } from "@heroui/skeleton";
import React from "react";

export const SkeletonManageGroups = () => {
  return (
    <Card className="flex h-full w-full flex-col gap-5 p-4" radius="sm">
      {/* Table headers */}
      <div className="hidden justify-between md:flex">
        <Skeleton className="w-1/12 rounded-lg">
          <div className="bg-default-200 h-8"></div>
        </Skeleton>
        <Skeleton className="w-2/12 rounded-lg">
          <div className="bg-default-200 h-8"></div>
        </Skeleton>
        <Skeleton className="w-2/12 rounded-lg">
          <div className="bg-default-200 h-8"></div>
        </Skeleton>
        <Skeleton className="w-2/12 rounded-lg">
          <div className="bg-default-200 h-8"></div>
        </Skeleton>
        <Skeleton className="w-2/12 rounded-lg">
          <div className="bg-default-200 h-8"></div>
        </Skeleton>
        <Skeleton className="w-1/12 rounded-lg">
          <div className="bg-default-200 h-8"></div>
        </Skeleton>
        <Skeleton className="w-1/12 rounded-lg">
          <div className="bg-default-200 h-8"></div>
        </Skeleton>
      </div>

      {/* Table body */}
      <div className="flex flex-col gap-3">
        {[...Array(3)].map((_, index) => (
          <div
            key={index}
            className="flex flex-col items-center justify-between md:flex-row md:gap-4"
          >
            <Skeleton className="mb-2 w-full rounded-lg md:mb-0 md:w-1/12">
              <div className="bg-default-300 h-12"></div>
            </Skeleton>
            <Skeleton className="mb-2 w-full rounded-lg md:mb-0 md:w-2/12">
              <div className="bg-default-300 h-12"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-2/12">
              <div className="bg-default-300 h-12"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-2/12">
              <div className="bg-default-300 h-12"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-2/12">
              <div className="bg-default-300 h-12"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-1/12">
              <div className="bg-default-300 h-12"></div>
            </Skeleton>
            <Skeleton className="mb-2 hidden rounded-lg sm:flex md:mb-0 md:w-1/12">
              <div className="bg-default-300 h-12"></div>
            </Skeleton>
          </div>
        ))}
      </div>
    </Card>
  );
};
