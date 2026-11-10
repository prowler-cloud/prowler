import { Radar } from "lucide-react";
import Link from "next/link";

import { Button, Card, CardContent } from "@/components/shadcn";
import { WIZARD_OPEN_SOURCE } from "@/lib/provider-funnel/provider-funnel-events";
import { buildAddProviderHref } from "@/lib/providers-navigation";

/** Realtime watches AWS accounts only; there is none to pick yet. */
export function RealtimeNoAccount() {
  return (
    <Card variant="base" padding="xl">
      <CardContent className="flex flex-col items-center gap-4 text-center">
        <Radar className="text-text-neutral-tertiary size-8" aria-hidden />
        <div className="flex max-w-md flex-col gap-1">
          <h2 className="text-text-neutral-primary text-lg font-semibold">
            Connect an AWS account first
          </h2>
          <p className="text-text-neutral-tertiary text-sm">
            Prowler Realtime watches an AWS account&apos;s CloudTrail as changes
            happen. Add an AWS provider to set it up.
          </p>
        </div>
        <Button asChild>
          <Link href={buildAddProviderHref(WIZARD_OPEN_SOURCE.EMPTY_STATE)}>
            Add AWS account
          </Link>
        </Button>
      </CardContent>
    </Card>
  );
}
