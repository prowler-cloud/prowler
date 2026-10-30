import { ReactNode } from "react";

import { DemoBadgeIfDemo } from "@/components/realtime/demo-context";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn/card/card";

interface RealtimeStatCardProps {
  title: string;
  children: ReactNode;
  /** Right-aligned content in the header, e.g. a badge. */
  adornment?: ReactNode;
}

/** The framed tile every overview figure sits in. */
export function RealtimeStatCard({
  title,
  children,
  adornment,
}: RealtimeStatCardProps) {
  return (
    <Card variant="base" className="gap-3">
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <CardTitle className="text-text-neutral-secondary mt-0 text-sm font-medium">
          {title}
        </CardTitle>
        <div className="flex items-center gap-2">
          <DemoBadgeIfDemo />
          {adornment}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">{children}</CardContent>
    </Card>
  );
}

export function StatFigure({
  value,
  caption,
}: {
  value: ReactNode;
  caption?: ReactNode;
}) {
  return (
    <div className="flex flex-col">
      <span className="text-text-neutral-primary text-3xl font-semibold">
        {value}
      </span>
      {caption && (
        <span className="text-text-neutral-tertiary text-xs">{caption}</span>
      )}
    </div>
  );
}

/** A label with a count on the right; `empty` renders when there is nothing. */
export function CountList({
  entries,
  empty,
  format = (key: string) => key,
}: {
  entries: Array<[string, number]>;
  empty: string;
  format?: (key: string) => string;
}) {
  if (entries.length === 0) {
    return <p className="text-text-neutral-tertiary text-sm">{empty}</p>;
  }
  return (
    <ul className="flex flex-col gap-1">
      {entries.map(([key, count]) => (
        <li
          key={key}
          className="flex items-center justify-between gap-2 text-sm"
        >
          <span className="text-text-neutral-secondary">{format(key)}</span>
          <span className="text-text-neutral-primary font-medium tabular-nums">
            {count}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** A titled block of a tab: heading, optional explanation, then content. */
export function RealtimeSection({
  title,
  description,
  action,
  children,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col gap-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex flex-col gap-1">
          <h3 className="text-text-neutral-primary flex items-center gap-2 text-base font-medium">
            {title}
            <DemoBadgeIfDemo />
          </h3>
          {description && (
            <p className="text-text-neutral-tertiary max-w-prose text-sm">
              {description}
            </p>
          )}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
