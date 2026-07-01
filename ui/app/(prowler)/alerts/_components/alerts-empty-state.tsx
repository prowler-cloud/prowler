import { BellRing, TagIcon } from "lucide-react";
import Link from "next/link";

import { Button, Card, CardContent } from "@/components/shadcn";

export const AlertsEmptyState = () => (
  <Card variant="base" padding="lg">
    <CardContent className="flex flex-col items-center gap-4 text-center">
      <div className="bg-button-primary/10 flex h-14 w-14 items-center justify-center rounded-full">
        <BellRing className="text-button-primary h-7 w-7" aria-hidden="true" />
      </div>
      <div className="flex flex-col gap-1">
        <h3 className="text-text-neutral-primary text-lg font-semibold">
          No alerts yet
        </h3>
        <p className="text-text-neutral-secondary max-w-md text-sm">
          Create alerts from Findings page to notify selected recipients when
          matching findings appear.
        </p>
      </div>
      <Button asChild size="sm">
        <Link href="/findings?filter[muted]=false&filter[status__in]=FAIL">
          <TagIcon size={14} aria-hidden="true" />
          Go to Findings
        </Link>
      </Button>
    </CardContent>
  </Card>
);
