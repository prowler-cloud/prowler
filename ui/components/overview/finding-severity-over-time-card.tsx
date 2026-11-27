import type { ReactNode } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";

export function FindingSeverityOverTimeCard({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <Card variant="base" className="flex h-full flex-1 flex-col">
      <CardHeader className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <CardTitle>Findings Severity Over Time</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col px-6">
        {children}
      </CardContent>
    </Card>
  );
}
