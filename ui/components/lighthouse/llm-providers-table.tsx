"use client";

import { Icon } from "@iconify/react";
import { useEffect, useState } from "react";

import {
  getLighthouseProviders,
  getTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import { CustomButton } from "@/components/ui/custom";

import { getAllProviders } from "./llm-provider-registry";

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
        const connectedProviders = new Map<string, any>();

        if (result.data && !result.errors) {
          result.data.forEach((provider: any) => {
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
            <div
              key={i}
              className="flex flex-col gap-4 rounded-lg border border-gray-200 bg-white p-6 dark:border-gray-800 dark:bg-gray-900"
            >
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 animate-pulse rounded-full bg-gray-200 dark:bg-gray-700" />
                <div className="flex flex-1 flex-col gap-2">
                  <div className="h-5 w-32 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                  <div className="h-3 w-48 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                </div>
              </div>

              <div className="flex-grow space-y-3">
                <div>
                  <div className="mb-2 h-4 w-16 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                  <div className="h-4 w-28 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                </div>
                <div>
                  <div className="mb-2 h-4 w-24 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                  <div className="h-4 w-36 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
                </div>
              </div>

              <div className="h-10 w-full animate-pulse rounded-lg bg-gray-200 dark:bg-gray-700" />
            </div>
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
            <div
              key={provider.id}
              className="flex flex-col gap-4 rounded-lg border border-gray-200 bg-white p-6 dark:border-gray-800 dark:bg-gray-900"
            >
              {/* Header */}
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

              {/* Status and Model Info */}
              <div className="flex-grow space-y-3">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    Status
                  </p>
                  <p
                    className={`text-sm ${
                      provider.isConnected && provider.isActive
                        ? "font-bold text-green-600 dark:text-green-500"
                        : "text-gray-500 dark:text-gray-500"
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
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Default Model
                    </p>
                    <p className="text-sm text-gray-700 dark:text-gray-300">
                      {provider.defaultModel}
                    </p>
                  </div>
                )}
              </div>

              {/* Action Button */}
              {showConnect && (
                <CustomButton
                  asLink={`/lighthouse/config/connect?provider=${provider.id}`}
                  ariaLabel={`Connect ${provider.provider}`}
                  variant="solid"
                  color="action"
                  size="md"
                  className="w-full"
                >
                  Connect
                </CustomButton>
              )}

              {showConfigure && (
                <CustomButton
                  asLink={`/lighthouse/config/configure?provider=${provider.id}`}
                  ariaLabel={`Configure ${provider.provider}`}
                  variant="bordered"
                  color="action"
                  size="md"
                  className="w-full"
                >
                  Configure
                </CustomButton>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
