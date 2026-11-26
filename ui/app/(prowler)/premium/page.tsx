import { LockKeyhole } from "lucide-react";
import { redirect } from "next/navigation";

import { PremiumComparison } from "@/components/premium/premium-comparison";
import { PremiumCtas } from "@/components/premium/premium-ctas";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { isCloud } from "@/lib/shared/env";
import {
  CLOUD_UPGRADE_FEATURE,
  CLOUD_UPGRADE_SURFACE,
} from "@/types/cloud-upgrade";

export default function PremiumPage() {
  if (isCloud()) redirect("/");

  return (
    <ContentLayout
      title="Open Source, Cloud and Private Cloud"
      icon={<LockKeyhole />}
    >
      <div className="max-w-5xl space-y-6">
        <p className="text-text-neutral-secondary text-sm">
          All three editions run the same Prowler engine. Your Local Server
          keeps everything it has today.
        </p>
        <PremiumComparison />
        <PremiumCtas
          feature={CLOUD_UPGRADE_FEATURE.GENERAL}
          surface={CLOUD_UPGRADE_SURFACE.PREMIUM_PAGE}
        />
      </div>
    </ContentLayout>
  );
}
