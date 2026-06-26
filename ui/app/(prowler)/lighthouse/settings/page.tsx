import { Spacer } from "@heroui/spacer";

import {
  getLighthouseV2Configurations,
  getLighthouseV2SupportedModels,
  getLighthouseV2SupportedProviders,
} from "@/app/(prowler)/lighthouse/_actions";
import { LighthouseV2ConfigPage } from "@/app/(prowler)/lighthouse/_components/config";
import type {
  LighthouseV2ProviderType,
  LighthouseV2SupportedModel,
} from "@/app/(prowler)/lighthouse/_types";
import {
  LighthouseSettings,
  LLMProvidersTable,
} from "@/components/lighthouse-v1";
import { ContentLayout } from "@/components/ui";
import { isCloud } from "@/lib/shared/env";

export const dynamic = "force-dynamic";

export default async function LighthouseSettingsPage() {
  if (isCloud()) {
    const [configurationsResult, providersResult] = await Promise.all([
      getLighthouseV2Configurations(),
      getLighthouseV2SupportedProviders(),
    ]);

    const providers = "data" in providersResult ? providersResult.data : [];
    const modelsEntries = await Promise.all(
      providers.map(async (provider) => {
        const result = await getLighthouseV2SupportedModels(provider.id);
        return [
          provider.id,
          "data" in result ? result.data : [],
        ] as const satisfies readonly [
          LighthouseV2ProviderType,
          LighthouseV2SupportedModel[],
        ];
      }),
    );
    const modelsByProvider = Object.fromEntries(modelsEntries) as Record<
      LighthouseV2ProviderType,
      LighthouseV2SupportedModel[]
    >;
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
          modelsByProvider={modelsByProvider}
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
