import { Card, Skeleton } from "@nextui-org/react";
import React from "react";

export const ComplianceSkeletonGrid = () => {
  return (
    <Card className="h-fit w-full p-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-3 3xl:grid-cols-4">
        {[...Array(28)].map((_, index) => (
          <div key={index} className="flex flex-col space-y-4">
            <Skeleton className="h-28 rounded-lg">
              <div className="h-full bg-default-300"></div>
            </Skeleton>
          </div>
        ))}
      </div>
    </Card>
  );
};
