"use client";

import { useEffect } from "react";
import { useForm, useWatch } from "react-hook-form";

import {
  RegistryUpgradePrompt,
  RegistrySetupPrompt,
} from "@/components/registry/registry-upgrade-prompt";
import { Button } from "@/components/shadcn";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Form } from "@/components/shadcn/form";
import { REGISTRY_PROVIDER_DISCOVERY } from "@/lib/registry/provider-options";
import { isRegistryEnabled } from "@/lib/shared/env";
import type { AddProviderFormValues, ProviderType } from "@/types";

import { RadioGroupProvider } from "../../radio-group-provider";

import { useRegistryProviderDiscovery } from "./use-registry-provider-discovery";

interface ProviderPickerProps {
  /** Reports the provider the user picked; the wizard moves to its connect step. */
  onProviderTypeChange: (providerType: ProviderType) => void;
}

/** Built-in and Registry providers to choose from before connecting one. */
export const ProviderPicker = ({
  onProviderTypeChange,
}: ProviderPickerProps) => {
  const {
    result: registryDiscovery,
    isRetryingDiscovery,
    retryDiscovery,
  } = useRegistryProviderDiscovery();
  const registryOptions =
    registryDiscovery?.status === REGISTRY_PROVIDER_DISCOVERY.READY
      ? registryDiscovery.options
      : [];
  // The deployment flag is known up front, so the tabs render before discovery.
  const registryAvailable =
    isRegistryEnabled() &&
    registryDiscovery?.status !== REGISTRY_PROVIDER_DISCOVERY.ACCESS_DENIED;
  const registryError =
    registryDiscovery?.status === REGISTRY_PROVIDER_DISCOVERY.ERROR ||
    registryDiscovery?.status === REGISTRY_PROVIDER_DISCOVERY.UNKNOWN;

  const form = useForm<AddProviderFormValues>({
    defaultValues: { providerType: undefined },
  });
  const providerType = useWatch({
    control: form.control,
    name: "providerType",
  });

  useEffect(() => {
    if (providerType) onProviderTypeChange(providerType);
  }, [onProviderTypeChange, providerType]);

  return (
    <Form {...form}>
      <div className="flex flex-col gap-4">
        <RadioGroupProvider
          registryAvailable={registryAvailable}
          registryLoading={registryAvailable && registryDiscovery === null}
          registryNotice={
            registryDiscovery?.status ===
            REGISTRY_PROVIDER_DISCOVERY.SUBSCRIPTION_REQUIRED ? (
              <RegistryUpgradePrompt />
            ) : registryDiscovery?.status ===
              REGISTRY_PROVIDER_DISCOVERY.ONBOARDING ? (
              <RegistrySetupPrompt />
            ) : (
              registryError && (
                <Alert variant="warning">
                  <AlertTitle>
                    Registry providers could not be loaded
                  </AlertTitle>
                  <AlertDescription>
                    Built-in providers are available. Check the Registry
                    connection and try again.
                    {/* aria-disabled, not disabled: the pressed button keeps focus. */}
                    <Button
                      type="button"
                      variant="outline"
                      aria-disabled={isRetryingDiscovery}
                      onClick={retryDiscovery}
                    >
                      {isRetryingDiscovery
                        ? "Retrying…"
                        : "Retry Registry providers"}
                    </Button>
                  </AlertDescription>
                </Alert>
              )
            )
          }
          registryOptions={registryOptions}
          control={form.control}
          isInvalid={!!form.formState.errors.providerType}
          errorMessage={form.formState.errors.providerType?.message}
        />
      </div>
    </Form>
  );
};
