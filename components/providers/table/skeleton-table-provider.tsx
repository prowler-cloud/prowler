import { Card, Skeleton } from "@nextui-org/react";
import React from "react";

export const SkeletonTableProvider = () => {
  return (
    <Card className="w-full h-full space-y-5 p-4" radius="sm">
      {/* Table headers */}
      <div className="hidden md:flex justify-between">
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
            className="flex flex-col md:flex-row justify-between items-center space-x-0 md:space-x-4"
          >
            <Skeleton className="w-full md:w-1/12 rounded-lg mb-2 md:mb-0">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="w-full md:w-2/12 rounded-lg mb-2 md:mb-0">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="hidden sm:flex md:w-2/12 rounded-lg mb-2 md:mb-0">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="hidden sm:flex md:w-2/12 rounded-lg mb-2 md:mb-0">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="hidden sm:flex md:w-2/12 rounded-lg mb-2 md:mb-0">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="hidden sm:flex md:w-1/12 rounded-lg mb-2 md:mb-0">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
            <Skeleton className="hidden sm:flex md:w-1/12 rounded-lg mb-2 md:mb-0">
              <div className="h-12 bg-default-300"></div>
            </Skeleton>
          </div>
        ))}
      </div>
    </Card>
  );
};
