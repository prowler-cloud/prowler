import { Spacer } from "@heroui/spacer";

import {
  getLighthouseV2Configurations,
  getLighthouseV2SupportedProviders,
  getLighthouseV2TenantConfiguration,
} from "@/app/(prowler)/lighthouse/_actions";
import { LighthouseV2ConfigPage } from "@/app/(prowler)/lighthouse/_components/config";
import {
  LighthouseSettings,
  LLMProvidersTable,
} from "@/components/lighthouse-v1";
import { ContentLayout } from "@/components/ui";
import { isCloud } from "@/lib/shared/env";

export const dynamic = "force-dynamic";

export default async function LighthouseSettingsPage() {
  if (isCloud()) {
    const [configurationsResult, providersResult, tenantConfigurationResult] =
      await Promise.all([
        getLighthouseV2Configurations(),
        getLighthouseV2SupportedProviders(),
        getLighthouseV2TenantConfiguration(),
      ]);

    const providers = "data" in providersResult ? providersResult.data : [];
    const error =
      "error" in configurationsResult
        ? configurationsResult.error
        : "error" in providersResult
          ? providersResult.error
          : undefined;

    return (
      <ContentLayout title="Settings">
        <LighthouseV2ConfigPage
          configurations={
            "data" in configurationsResult ? configurationsResult.data : []
          }
          providers={providers}
          tenantConfiguration={
            "data" in tenantConfigurationResult
              ? tenantConfigurationResult.data
              : undefined
          }
          error={error}
        />
      </ContentLayout>
    );
  }

  return (
    <ContentLayout title="Settings">
      <LLMProvidersTable />
      <Spacer y={8} />
      <LighthouseSettings />
    </ContentLayout>
  );
}
