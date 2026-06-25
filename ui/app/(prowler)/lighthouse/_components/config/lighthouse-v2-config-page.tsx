"use client";

import { useState } from "react";

import {
  FEEDBACK_VARIANT,
  type FeedbackState,
} from "@/app/(prowler)/lighthouse/_lib/config";
import {
  type LighthouseV2Configuration,
  type LighthouseV2ProviderType,
  type LighthouseV2SupportedModel,
  type LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { Card } from "@/components/shadcn/card/card";

import { LighthouseV2ConfigurationForm } from "./configuration-form";
import { LighthouseV2EmptyState } from "./empty-state";
import { ConfigFeedbackAlert } from "./feedback-alert";
import { LighthouseV2ProviderRail } from "./provider-rail";

interface LighthouseV2ConfigPageProps {
  configurations: LighthouseV2Configuration[];
  providers: LighthouseV2SupportedProvider[];
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >;
  error?: string;
}

export function LighthouseV2ConfigPage({
  configurations,
  providers,
  modelsByProvider,
  error,
}: LighthouseV2ConfigPageProps) {
  const [localConfigurations, setLocalConfigurations] =
    useState(configurations);
  const [selectedProvider, setSelectedProvider] =
    useState<LighthouseV2ProviderType>(providers[0]?.id ?? "openai");
  const [feedback, setFeedback] = useState<FeedbackState | null>(
    error
      ? {
          title: "Configuration unavailable",
          description: error,
          variant: FEEDBACK_VARIANT.ERROR,
        }
      : null,
  );

  const selectedConfig = localConfigurations.find(
    (config) => config.providerType === selectedProvider,
  );
  const selectedProviderDefinition =
    providers.find((provider) => provider.id === selectedProvider) ??
    providers[0];
  const selectedModels =
    selectedProviderDefinition &&
    modelsByProvider[selectedProviderDefinition.id]
      ? modelsByProvider[selectedProviderDefinition.id]
      : [];

  const upsertConfiguration = (configuration: LighthouseV2Configuration) => {
    setLocalConfigurations((current) => [
      ...current.filter((config) => config.id !== configuration.id),
      configuration,
    ]);
  };

  const handleConfigurationSaved = (
    configuration: LighthouseV2Configuration,
  ) => {
    upsertConfiguration(configuration);
    setSelectedProvider(configuration.providerType);
    setFeedback({
      title: "Configuration saved.",
      description: "Lighthouse can use this provider after it tests cleanly.",
      variant: FEEDBACK_VARIANT.SUCCESS,
    });
  };

  const handleConfigurationTested = (
    configuration: LighthouseV2Configuration,
  ) => {
    upsertConfiguration(configuration);
    setFeedback(
      configuration.connected
        ? {
            title: "Connection successful.",
            description: "Lighthouse can send messages with this provider.",
            variant: FEEDBACK_VARIANT.SUCCESS,
          }
        : {
            title: "Connection failed.",
            description:
              "Review the credentials and test the connection again.",
            variant: FEEDBACK_VARIANT.ERROR,
          },
    );
  };

  const handleConfigurationDeleted = (configurationId: string) => {
    setLocalConfigurations((current) =>
      current.filter((config) => config.id !== configurationId),
    );
    setFeedback({
      title: "Configuration removed.",
      description: "This provider is no longer available for Lighthouse.",
      variant: FEEDBACK_VARIANT.INFO,
    });
  };

  if (providers.length === 0 || !selectedProviderDefinition) {
    return <LighthouseV2EmptyState error={error} />;
  }

  return (
    <Card
      variant="base"
      padding="none"
      role="region"
      aria-label="Lighthouse settings"
      className="min-h-[calc(100dvh-6.5rem)] w-full gap-0 overflow-hidden"
    >
      {feedback && (
        <div className="border-border-neutral-secondary border-b px-4 py-4 md:px-5">
          <ConfigFeedbackAlert
            feedback={feedback}
            onClose={() => setFeedback(null)}
          />
        </div>
      )}

      <div className="grid min-h-0 gap-0 xl:grid-cols-[320px_auto_minmax(0,1fr)]">
        <div className="min-w-0 p-4 md:p-5">
          <LighthouseV2ProviderRail
            configurations={localConfigurations}
            providers={providers}
            selectedProvider={selectedProvider}
            onSelectProvider={(provider) => {
              setSelectedProvider(provider);
              setFeedback(null);
            }}
          />
        </div>

        <div
          data-slot="settings-separator"
          aria-hidden="true"
          className="border-border-neutral-secondary border-t xl:border-t-0 xl:border-l"
        />

        <div className="min-w-0">
          <LighthouseV2ConfigurationForm
            key={selectedProvider}
            configuration={selectedConfig}
            models={selectedModels}
            provider={selectedProviderDefinition}
            onConfigurationSaved={handleConfigurationSaved}
            onConfigurationDeleted={handleConfigurationDeleted}
            onConfigurationTested={handleConfigurationTested}
            onFeedback={setFeedback}
          />
        </div>
      </div>
    </Card>
  );
}
