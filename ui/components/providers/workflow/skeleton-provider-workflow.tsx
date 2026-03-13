import { Card, CardContent, CardHeader } from "@/components/shadcn/card/card";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

export const SkeletonProviderWorkflow = () => {
  return (
    <Card variant="inner">
      <CardHeader className="flex flex-col items-start gap-2">
        <Skeleton className="h-6 w-2/3 rounded-lg" />
        <Skeleton className="h-4 w-1/2 rounded-lg" />
      </CardHeader>
      <CardContent className="flex flex-col items-start gap-6">
        <div className="flex gap-4">
          <Skeleton className="h-12 w-12 rounded-lg" />
          <Skeleton className="h-12 w-12 rounded-lg" />
        </div>
        <Skeleton className="h-5 w-3/4 rounded-lg" />
        <Skeleton className="h-12 w-40 self-end rounded-lg" />
      </CardContent>
    </Card>
  );
};
