import Link from "next/link";

import { AttackSurfaceItem } from "@/actions/overview";
import { Card, CardContent } from "@/components/shadcn";

interface AttackSurfaceCardItemProps {
  item: AttackSurfaceItem;
}

export function AttackSurfaceCardItem({ item }: AttackSurfaceCardItemProps) {
  const hasCheckIds = item.checkIds.length > 0;
  const findingsUrl = hasCheckIds
    ? `/findings?filter[check_id__in]=${item.checkIds.join(",")}&filter[status__in]=FAIL`
    : null;

  const cardContent = (
    <Card
      variant="inner"
      padding="md"
      className={`flex min-h-[120px] min-w-[200px] flex-1 flex-col justify-between ${hasCheckIds ? "cursor-pointer transition-colors hover:bg-accent" : ""}`}
      aria-label={`${item.label}: ${item.failedFindings} failed findings`}
    >
      <CardContent className="flex flex-col gap-2 p-0">
        <span
          className="text-5xl leading-none font-light tracking-tight"
          aria-hidden="true"
        >
          {item.failedFindings}
        </span>
        <span className="text-text-neutral-tertiary text-sm leading-6">
          {item.label}
        </span>
      </CardContent>
    </Card>
  );

  if (findingsUrl) {
    return <Link href={findingsUrl}>{cardContent}</Link>;
  }

  return cardContent;
}
