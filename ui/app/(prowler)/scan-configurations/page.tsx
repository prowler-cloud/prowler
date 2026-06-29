import { redirect } from "next/navigation";

import { getAllProviders } from "@/actions/providers";
import {
  getScanConfigurationSchema,
  listScanConfigurations,
} from "@/actions/scan-configurations";
import { ContentLayout } from "@/components/ui";
import { isCloud } from "@/lib/shared/env";

import { ScanConfigurationsManager } from "./_components/scan-configurations-manager";

export default async function ScanConfigPage() {
  // Scan Configuration is a Prowler Cloud-only feature; the OSS API has no
  // /scan-configurations endpoints, so guard the route before hitting them.
  if (!isCloud()) {
    redirect("/");
  }

  // A failure here propagates to the `(prowler)/error.tsx` boundary instead of
  // rendering a false "no scan configurations" empty table during SSR.
  const [configs, providersResponse, schema] = await Promise.all([
    listScanConfigurations(),
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
