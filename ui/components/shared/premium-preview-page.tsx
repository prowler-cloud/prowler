import { LockKeyhole } from "lucide-react";
import type { ReactNode } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { PremiumBadge } from "@/components/shared/premium-badge";
import { PremiumCtas } from "@/components/shared/premium-ctas";
import {
  CLOUD_UPGRADE_CONTENT,
  CLOUD_UPGRADE_FOOTER_NOTE,
} from "@/lib/cloud-upgrade";
import type { PremiumPreviewFeature } from "@/lib/premium-preview";
import { CLOUD_UPGRADE_SURFACE } from "@/types/cloud-upgrade";

interface PremiumPreviewPageProps {
  feature: PremiumPreviewFeature;
  personalHook: ReactNode;
}

export function PremiumPreviewPage({
  feature,
  personalHook,
}: PremiumPreviewPageProps) {
  const content = CLOUD_UPGRADE_CONTENT[feature];

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <Card variant="base" padding="lg" className="gap-4">
        <PremiumBadge
          feature={feature}
          surface={CLOUD_UPGRADE_SURFACE.PREVIEW_PAGE}
        />
        <div className="flex flex-col gap-2">
          <h2 className="text-text-neutral-primary text-xl font-semibold">
            {content.title}
          </h2>
          <p className="text-text-neutral-secondary text-sm">
            {content.description}
          </p>
        </div>
        <Alert role="note">
          <LockKeyhole aria-hidden="true" />
          <AlertTitle>From your Local Server</AlertTitle>
          <AlertDescription>{personalHook}</AlertDescription>
        </Alert>
        <PremiumCtas
          feature={feature}
          surface={CLOUD_UPGRADE_SURFACE.PREVIEW_PAGE}
        />
      </Card>

      <ol className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {content.benefits.map((benefit, index) => (
          <li key={benefit} className="flex">
            <Card variant="inner" className="flex-1 gap-2">
              <span className="text-text-neutral-tertiary flex items-center gap-1 text-xs font-medium">
                <LockKeyhole aria-hidden="true" className="size-3" />
                Step {index + 1}
              </span>
              <CardContent className="text-text-neutral-primary text-sm">
                {benefit}
              </CardContent>
            </Card>
          </li>
        ))}
      </ol>

      <p className="text-text-neutral-tertiary text-xs">
        {CLOUD_UPGRADE_FOOTER_NOTE}
      </p>
    </div>
  );
}
