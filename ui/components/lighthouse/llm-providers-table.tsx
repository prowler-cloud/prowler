"use client";

import { Icon } from "@iconify/react";
import Link from "next/link";
import { useEffect, useState } from "react";

import {
  getLighthouseProviders,
  getTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import { Button, Card, CardContent, CardHeader } from "@/components/shadcn";

import { getAllProviders } from "./llm-provider-registry";

interface LighthouseProviderResource {
  id: string;
  attributes: {
    provider_type: string;
    is_active: boolean;
  };
}

type LLMProvider = {
  id: string;
  provider: string;
  description: string;
  defaultModel: string;
  icon: string;
  isConnected: boolean;
  isActive: boolean;
  isDefaultProvider: boolean;
};

export const LLMProvidersTable = () => {
  const [providers, setProviders] = useState<LLMProvider[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchProviders = async () => {
      setIsLoading(true);
      try {
        // Fetch connected providers from API
        const result = await getLighthouseProviders();
        const connectedProviders = new Map<
          string,
          LighthouseProviderResource
        >();

        if (result.data && !result.errors) {
          result.data.forEach((provider: LighthouseProviderResource) => {
            connectedProviders.set(provider.attributes.provider_type, provider);
          });
        }

        // Fetch tenant config for default models and default provider
        const configResult = await getTenantConfig();
        const defaultModels =
          configResult.data?.attributes?.default_models || {};
        const defaultProvider =
          configResult.data?.attributes?.default_provider || "";

        // Build provider list from registry
        const allProviders: LLMProvider[] = getAllProviders().map((config) => {
          const connected = connectedProviders.get(config.id);
          const defaultModel = defaultModels[config.id] || "";

          return {
            id: config.id,
            provider: config.name,
            description: config.description,
            icon: config.icon,
            defaultModel,
            isConnected: !!connected,
            isActive: connected?.attributes?.is_active || false,
            isDefaultProvider: config.id === defaultProvider,
          };
        });

        setProviders(allProviders);
      } catch (error) {
        console.error("Failed to fetch providers:", error);
        // Fallback to showing all providers from registry as not connected
        const allProviders: LLMProvider[] = getAllProviders().map((config) => ({
          id: config.id,
          provider: config.name,
          description: config.description,
          icon: config.icon,
          defaultModel: "",
          isConnected: false,
          isActive: false,
          isDefaultProvider: false,
        }));
        setProviders(allProviders);
      } finally {
        setIsLoading(false);
      }
    };

    fetchProviders();
  }, []);

  if (isLoading) {
    return (
      <div>
        <h2 className="mb-4 text-xl font-semibold">LLM Providers</h2>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <Card key={i} variant="base" padding="lg">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="bg-bg-neutral-tertiary h-10 w-10 animate-pulse rounded-full" />
                  <div className="flex flex-1 flex-col gap-2">
                    <div className="bg-bg-neutral-tertiary h-5 w-32 animate-pulse rounded" />
                    <div className="bg-bg-neutral-tertiary h-3 w-48 animate-pulse rounded" />
                  </div>
                </div>
              </CardHeader>

              <CardContent className="flex flex-col gap-4">
                <div className="flex-grow space-y-3">
                  <div>
                    <div className="bg-bg-neutral-tertiary mb-2 h-4 w-16 animate-pulse rounded" />
                    <div className="bg-bg-neutral-tertiary h-4 w-28 animate-pulse rounded" />
                  </div>
                  <div>
                    <div className="bg-bg-neutral-tertiary mb-2 h-4 w-24 animate-pulse rounded" />
                    <div className="bg-bg-neutral-tertiary h-4 w-36 animate-pulse rounded" />
                  </div>
                </div>

                <div className="bg-bg-neutral-tertiary h-10 w-full animate-pulse rounded-lg" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="mb-4 text-xl font-semibold">LLM Providers</h2>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        {providers.map((provider) => {
          // Show Connect button if not connected, Configure if connected
          const showConnect = !provider.isConnected;
          const showConfigure = provider.isConnected;

          return (
            <Card
              key={provider.id}
              variant="base"
              padding="lg"
              className="h-full"
            >
              {/* Header */}
              <CardHeader>
                <div className="flex items-center gap-3">
                  <Icon icon={provider.icon} width={40} height={40} />
                  <div className="flex flex-1 flex-col">
                    <div className="flex items-center gap-2">
                      <h3 className="text-lg font-semibold">
                        {provider.provider}
                      </h3>
                      {provider.isDefaultProvider && (
                        <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">
                          Default
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {provider.description}
                    </p>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="flex flex-1 flex-col justify-between gap-4">
                {/* Status and Model Info */}
                <div className="space-y-3">
                  <div>
                    <p className="text-text-neutral-secondary text-sm">
                      Status
                    </p>
                    <p
                      className={`text-sm ${
                        provider.isConnected && provider.isActive
                          ? "text-button-primary font-bold"
                          : "text-text-neutral-secondary text-sm"
                      }`}
                    >
                      {provider.isConnected
                        ? provider.isActive
                          ? "Connected"
                          : "Connection Failed"
                        : "Not configured"}
                    </p>
                  </div>

                  {provider.defaultModel && (
                    <div>
                      <p className="text-text-neutral-secondary text-sm">
                        Default Model
                      </p>
                      <p className="text-text-neutral-secondary text-sm">
                        {provider.defaultModel}
                      </p>
                    </div>
                  )}
                </div>

                {/* Action Button */}
                {showConnect && (
                  <Button
                    aria-label={`Connect ${provider.provider}`}
                    className="w-full"
                    asChild
                  >
                    <Link
                      href={`/lighthouse/config/connect?provider=${provider.id}`}
                    >
                      Connect
                    </Link>
                  </Button>
                )}

                {showConfigure && (
                  <Button
                    aria-label={`Configure ${provider.provider}`}
                    variant="outline"
                    className="w-full"
                    asChild
                  >
                    <Link
                      href={`/lighthouse/config/connect?provider=${provider.id}&mode=edit`}
                    >
                      Configure
                    </Link>
                  </Button>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
};
