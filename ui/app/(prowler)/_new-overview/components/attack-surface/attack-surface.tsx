"use client";

import { CircleAlert } from "lucide-react";

import { AttackSurfaceItem } from "@/actions/overview";
import { Card, CardContent, CardTitle, Skeleton } from "@/components/shadcn";

interface AttackSurfaceCardItemProps {
  item: AttackSurfaceItem;
}

function AttackSurfaceCardItem({ item }: AttackSurfaceCardItemProps) {
  return (
    <Card
      variant="inner"
      padding="md"
      className="relative flex min-h-[120px] min-w-[200px] flex-1 flex-col justify-between"
      aria-label={`${item.label}: ${item.failedFindings} failed findings`}
    >
      {item.hasFailures && (
        <CircleAlert
          size={20}
          className="text-text-error-primary absolute top-3 right-3"
          aria-label="Has failed findings"
        />
      )}
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
}

interface AttackSurfaceProps {
  items: AttackSurfaceItem[];
}

export function AttackSurface({ items }: AttackSurfaceProps) {
  const isEmpty = items.length === 0;

  return (
    <Card variant="base" className="flex w-full flex-col">
      <CardTitle>Attack Surface</CardTitle>
      <CardContent className="mt-4 flex flex-wrap gap-4">
        {isEmpty ? (
          <div className="flex w-full items-center justify-center py-8">
            <p className="text-text-neutral-tertiary text-sm">
              No attack surface data available.
            </p>
          </div>
        ) : (
          items.map((item) => (
            <AttackSurfaceCardItem key={item.id} item={item} />
          ))
        )}
      </CardContent>
    </Card>
  );
}

export function AttackSurfaceSkeleton() {
  return (
    <Card variant="base" className="flex w-full flex-col">
      <Skeleton className="h-7 w-32 rounded-xl" />
      <CardContent className="mt-4 flex flex-wrap gap-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Card
            key={index}
            variant="inner"
            padding="md"
            className="flex min-h-[120px] min-w-[200px] flex-1 flex-col justify-between"
          >
            <div className="flex flex-col gap-2">
              <Skeleton className="h-12 w-20 rounded-xl" />
              <Skeleton className="h-5 w-40 rounded-xl" />
            </div>
          </Card>
        ))}
      </CardContent>
    </Card>
  );
}
