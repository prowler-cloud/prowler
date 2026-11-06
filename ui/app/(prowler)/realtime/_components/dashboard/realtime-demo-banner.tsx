import { FlaskConical } from "lucide-react";
import Link from "next/link";

import {
  configurationHref,
  LIGHTHOUSE_CHAT_PATH,
} from "@/app/(prowler)/realtime/_lib/routes";
import { Badge, Button, Card, CardContent } from "@/components/shadcn";

interface RealtimeDemoBannerProps {
  providerId: string;
}

/** The one place that says the data is made up, instead of a badge per card. */
export function RealtimeDemoBanner({ providerId }: RealtimeDemoBannerProps) {
  return (
    <Card variant="base" padding="lg">
      <CardContent className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-start gap-3">
          <FlaskConical
            className="text-bg-data-info mt-0.5 size-5 shrink-0"
            aria-hidden
          />
          <div className="flex max-w-3xl flex-col gap-1">
            <div className="flex items-center gap-2">
              <h2 className="text-text-neutral-primary text-sm font-semibold">
                You are exploring demo data
              </h2>
              <Badge variant="info" size="sm">
                Demo
              </Badge>
            </div>
            <p className="text-text-neutral-secondary text-sm">
              It comes from a made-up AWS account. Set up Prowler Realtime to
              watch this account as changes happen. It starts in dry run, so
              nothing changes until you decide.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <Button variant="outline" asChild>
            <Link href={LIGHTHOUSE_CHAT_PATH}>Set up with Lighthouse AI</Link>
          </Button>
          <Button asChild>
            <Link href={configurationHref(providerId)}>Set up Realtime</Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
