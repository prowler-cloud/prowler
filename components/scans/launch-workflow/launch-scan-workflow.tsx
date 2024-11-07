import { getProviders } from "@/actions/providers/providers";
import { ProviderProps } from "@/types";

import { SelectScanProvider } from "./select-scan-provider";

export const LaunchScanWorkflow = async () => {
  // const providersData = await getProviders({
  //   filters: { "filter[connected]": "true" },
  // });
  const providersData = await getProviders({});

  const providerInfo = providersData?.data?.length
    ? providersData.data.map((provider: ProviderProps) => ({
        alias: provider.attributes.alias,
        providerType: provider.attributes.provider,
        uid: provider.attributes.uid,
        connected: provider.attributes.connection.connected,
      }))
    : [];

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="flex flex-col gap-2">
          <span className="text-sm text-default-500">Launch Scan</span>
          <SelectScanProvider providers={providerInfo} />
        </div>
      </div>
    </div>
  );
};
