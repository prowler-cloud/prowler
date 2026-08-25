import { listScanConfigurations } from "@/actions/scan-configurations";
import { ProvidersAccountsView } from "@/components/providers/providers-accounts-view";
import { isCloud } from "@/lib/shared/env";
import { SearchParamsProps } from "@/types";
import {
  SCAN_CONFIGURATION_LIST_STATUS,
  type ScanConfigurationListState,
} from "@/types/scan-configurations";

import { loadProvidersAccountsViewData } from "./providers-page.utils";

const loadScanConfigs = async (
  isCloud: boolean,
): Promise<ScanConfigurationListState> => {
  if (!isCloud) {
    return { status: SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE, data: [] };
  }

  try {
    return {
      status: SCAN_CONFIGURATION_LIST_STATUS.AVAILABLE,
      data: await listScanConfigurations(),
    };
  } catch (error) {
    console.error("Error loading provider scan configurations:", error);
    return { status: SCAN_CONFIGURATION_LIST_STATUS.UNAVAILABLE, data: [] };
  }
};

export const ProvidersTabContent = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) => {
  const isCloudEnvironment = isCloud();
  const [providersView, scanConfigsState] = await Promise.all([
    loadProvidersAccountsViewData({
      searchParams,
      isCloud: isCloudEnvironment,
    }),
    loadScanConfigs(isCloudEnvironment),
  ]);

  return (
    <ProvidersAccountsView
      isCloud={isCloudEnvironment}
      filters={providersView.filters}
      providers={providersView.providers}
      providerGroups={providersView.providerGroups}
      metadata={providersView.metadata}
      rows={providersView.rows}
      hierarchyStatus={providersView.hierarchyStatus}
      scanConfigs={scanConfigsState.data}
      scanConfigStatus={scanConfigsState.status}
    />
  );
};
