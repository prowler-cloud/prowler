import { LockKeyhole } from "lucide-react";

import { PremiumCtas } from "@/components/premium/premium-ctas";
import { PremiumBadge } from "@/components/shared/premium-badge";
import { CLOUD_UPGRADE_CONTENT } from "@/lib/cloud-upgrade";
import type { PremiumPreviewFeature } from "@/lib/premium-preview";
import { CLOUD_UPGRADE_SURFACE } from "@/types/cloud-upgrade";

interface PremiumPreviewPageProps {
  feature: PremiumPreviewFeature;
  personalHook: string;
}

export function PremiumPreviewPage({
  feature,
  personalHook,
}: PremiumPreviewPageProps) {
  const content = CLOUD_UPGRADE_CONTENT[feature];

  return (
    <div className="flex max-w-5xl flex-col gap-6">
      <section className="border-border-neutral-secondary bg-bg-neutral-secondary flex flex-col gap-4 rounded-xl border p-6">
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
        <p className="border-border-neutral-secondary text-text-neutral-primary rounded-lg border px-3 py-2 text-sm">
          <span className="font-medium">From your Local Server: </span>
          {personalHook}
        </p>
        <PremiumCtas
          feature={feature}
          surface={CLOUD_UPGRADE_SURFACE.PREVIEW_PAGE}
        />
      </section>

      <ol className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {content.benefits.map((benefit, index) => (
          <li
            key={benefit}
            className="border-border-neutral-secondary flex flex-col gap-2 rounded-xl border p-4"
          >
            <span className="text-text-neutral-tertiary flex items-center gap-1 text-xs font-medium">
              <LockKeyhole aria-hidden="true" className="size-3" />
              Step {index + 1}
            </span>
            <p className="text-text-neutral-primary text-sm">{benefit}</p>
          </li>
        ))}
      </ol>

      <p className="text-text-neutral-tertiary text-xs">
        Prowler Cloud and Private Cloud run the same engine as your Local
        Server. Your Local Server stays unchanged.
      </p>
    </div>
  );
}
