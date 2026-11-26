import { LockKeyhole } from "lucide-react";
import { notFound } from "next/navigation";

import { PremiumComparison } from "@/app/(prowler)/premium/_components";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { PremiumCtas } from "@/components/shared/premium-ctas";
import { isCloud } from "@/lib/shared/env";
import {
  CLOUD_UPGRADE_FEATURE,
  CLOUD_UPGRADE_SURFACE,
} from "@/types/cloud-upgrade";

export default function PremiumPage() {
  if (isCloud()) notFound();

  return (
    <ContentLayout title="Compare editions" icon={<LockKeyhole />}>
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
