import { Button } from "@/components/shadcn/button/button";
import {
  CLOUD_UPGRADE_SALES_CTA,
  getCloudUpgradePrimaryCta,
  getCloudUpgradePrimaryUrl,
  getPrivateCloudContactUrl,
} from "@/lib/cloud-upgrade";
import type {
  CloudUpgradeFeature,
  CloudUpgradeSurface,
} from "@/types/cloud-upgrade";

interface PremiumCtasProps {
  feature: CloudUpgradeFeature;
  surface: CloudUpgradeSurface;
}

export function PremiumCtas({ feature, surface }: PremiumCtasProps) {
  const primaryCta = getCloudUpgradePrimaryCta(feature);

  return (
    <div className="space-y-2">
      <div className="flex flex-col gap-3 sm:flex-row">
        <Button asChild>
          <a
            href={getCloudUpgradePrimaryUrl(feature, surface)}
            target="_blank"
            rel="noopener noreferrer"
          >
            {primaryCta.label}
          </a>
        </Button>
        <Button asChild variant="outline">
          <a
            href={getPrivateCloudContactUrl(feature, surface)}
            target="_blank"
            rel="noopener noreferrer"
          >
            {CLOUD_UPGRADE_SALES_CTA}
          </a>
        </Button>
      </div>
      <p className="text-text-neutral-tertiary text-xs">{primaryCta.note}</p>
    </div>
  );
}
