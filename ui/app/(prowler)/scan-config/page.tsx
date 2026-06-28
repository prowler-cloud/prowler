import { redirect } from "next/navigation";

import { getAllProviders } from "@/actions/providers";
import { getScanConfigSchema, listScanConfigs } from "@/actions/scan-configs";
import { ContentLayout } from "@/components/ui";
import { isCloud } from "@/lib/shared/env";

import { ScanConfigsManager } from "./_components/scan-configs-manager";

export default async function ScanConfigPage() {
  // Scan Config is a Prowler Cloud-only feature; the OSS API has no
  // /scan-configs endpoints, so guard the route before hitting them.
  if (!isCloud()) {
    redirect("/");
  }

  const [configs, providersResponse, schema] = await Promise.all([
    listScanConfigs(),
    getAllProviders({}),
    getScanConfigSchema(),
  ]);

  const richProviders = providersResponse?.data ?? [];

  return (
    <ContentLayout title="Scan Config" icon="lucide:sliders">
      <ScanConfigsManager
        initialConfigs={configs}
        richProviders={richProviders}
        schema={schema}
      />
    </ContentLayout>
  );
}
