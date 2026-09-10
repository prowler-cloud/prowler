"use client";

import { useState } from "react";

import {
  FEEDBACK_VARIANT,
  type FeedbackState,
} from "@/app/(prowler)/lighthouse/_lib/config";
import {
  type LighthouseV2Configuration,
  type LighthouseV2ProviderType,
  type LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { useToast } from "@/components/shadcn";
import { Card } from "@/components/shadcn/card/card";
import { useMountEffect } from "@/hooks/use-mount-effect";

import { LighthouseV2BusinessContextForm } from "./business-context-form";
import { LighthouseV2ConfigurationForm } from "./configuration-form";
import { LighthouseV2EmptyState } from "./empty-state";
import { LighthouseV2ProviderRail } from "./provider-rail";

interface LighthouseV2ConfigPageProps {
  configurations: LighthouseV2Configuration[];
  providers: LighthouseV2SupportedProvider[];
  error?: string;
}

export function LighthouseV2ConfigPage({
  configurations,
  providers,
  error,
}: LighthouseV2ConfigPageProps) {
  const { toast } = useToast();
  const [localConfigurations, setLocalConfigurations] =
    useState(configurations);
  const [selectedProvider, setSelectedProvider] =
    useState<LighthouseV2ProviderType>(providers[0]?.id ?? "openai");

  const showFeedback = (feedback: FeedbackState) => {
    toast({
      title: feedback.title,
      description: feedback.description,
      variant:
        feedback.variant === FEEDBACK_VARIANT.ERROR ? "destructive" : "default",
    });
  };

  // Surface a load-time error (failed fetch) once, since it is not tied to a
  // user interaction that could dispatch the toast itself.
  useMountEffect(() => {
    if (error) {
      showFeedback({
        title: "Configuration unavailable",
        description: error,
        variant: FEEDBACK_VARIANT.ERROR,
      });
    }
  });

  // Business context is shared across every provider (the backend syncs it on
  // update), so it is edited once against any single configuration.
  const businessContextConfig = localConfigurations[0];

  const selectedConfig = localConfigurations.find(
    (config) => config.providerType === selectedProvider,
  );
  const selectedProviderDefinition =
    providers.find((provider) => provider.id === selectedProvider) ??
    providers[0];

  // Replace in place (don't filter+append): the shared business-context editor
  // is anchored to localConfigurations[0], so reordering on every save/test
  // would silently retarget it to a different provider's configuration.
  const upsertConfiguration = (configuration: LighthouseV2Configuration) => {
    setLocalConfigurations((current) => {
      const index = current.findIndex(
        (config) => config.id === configuration.id,
      );
      if (index === -1) {
        return [...current, configuration];
      }
      const next = [...current];
      next[index] = configuration;
      return next;
    });
  };

  const handleConfigurationSaved = (
    configuration: LighthouseV2Configuration,
  ) => {
    upsertConfiguration(configuration);
    setSelectedProvider(configuration.providerType);
    showFeedback({
      title: "Configuration saved.",
      description:
        "Lighthouse AI can use this provider after it tests cleanly.",
      variant: FEEDBACK_VARIANT.SUCCESS,
    });
  };

  const handleConfigurationTested = (
    configuration: LighthouseV2Configuration,
  ) => {
    upsertConfiguration(configuration);
    showFeedback(
      configuration.connected
        ? {
            title: "Connection successful.",
            description: "Lighthouse AI can send messages with this provider.",
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
    showFeedback({
      title: "Configuration removed.",
      description: "This provider is no longer available for Lighthouse AI.",
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
      aria-label="Lighthouse AI settings"
      className="w-full gap-4 p-4 md:p-5"
    >
      {businessContextConfig ? (
        <LighthouseV2BusinessContextForm
          key={businessContextConfig.id}
          configurationId={businessContextConfig.id}
          initialBusinessContext={businessContextConfig.businessContext}
        />
      ) : (
        <Card
          variant="inner"
          padding="md"
          data-lighthouse-v2-business-context-empty=""
          className="text-text-neutral-secondary text-sm"
        >
          Configure a provider first to add shared business context.
        </Card>
      )}

      <div className="grid min-h-0 flex-1 gap-4 xl:grid-cols-[320px_minmax(0,1fr)]">
        <LighthouseV2ProviderRail
          configurations={localConfigurations}
          providers={providers}
          selectedProvider={selectedProvider}
          onSelectProvider={setSelectedProvider}
        />

        <LighthouseV2ConfigurationForm
          key={selectedProvider}
          configuration={selectedConfig}
          provider={selectedProviderDefinition}
          onConfigurationSaved={handleConfigurationSaved}
          onConfigurationDeleted={handleConfigurationDeleted}
          onConfigurationTested={handleConfigurationTested}
          onFeedback={(feedback) => {
            if (feedback) showFeedback(feedback);
          }}
        />
      </div>
    </Card>
  );
}
