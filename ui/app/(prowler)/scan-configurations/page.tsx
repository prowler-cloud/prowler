import { redirect } from "next/navigation";

import { getAllProviders } from "@/actions/providers";
import {
  getScanConfigurationSchema,
  listScanConfigurations,
} from "@/actions/scan-configurations";
import { ContentLayout } from "@/components/ui";
import { isCloud } from "@/lib/shared/env";
import { ScanConfigurationData } from "@/types/scan-configurations";

import { ScanConfigurationsManager } from "./_components/scan-configurations-manager";

export default async function ScanConfigPage() {
  // Scan Configuration is a Prowler Cloud-only feature; the OSS API has no
  // /scan-configurations endpoints, so guard the route before hitting them.
  if (!isCloud()) {
    redirect("/");
  }

  const [configs, providersResponse, schema] = await Promise.all([
    // On initial load a failure falls back to an empty list; the client-side
    // refresh surfaces errors via a toast instead of clearing the table.
    listScanConfigurations().catch(() => [] as ScanConfigurationData[]),
    getAllProviders({}),
    getScanConfigurationSchema(),
  ]);

  const richProviders = providersResponse?.data ?? [];

  return (
    <ContentLayout title="Scan Configuration" icon="lucide:sliders">
      <ScanConfigurationsManager
        initialConfigs={configs}
        richProviders={richProviders}
        schema={schema}
      />
    </ContentLayout>
  );
}
