import type { ReactNode } from "react";

import { Card, CardContent } from "@/components/shadcn/card/card";

export const ComplianceOverviewPanel = ({
  children,
}: {
  children: ReactNode;
}) => {
  return (
    <Card
      variant="base"
      padding="none"
      className="minimal-scrollbar relative z-0 w-full gap-4 overflow-auto shadow-sm"
    >
      <CardContent className="flex flex-col gap-4 p-4">{children}</CardContent>
    </Card>
  );
};
