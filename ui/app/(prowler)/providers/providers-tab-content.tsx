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
  // The React Compiler (`reactCompiler: true`) otherwise instruments this as a
  // client component and injects `useMemoCache`, which needs a React dispatcher.
  // An async server component renders once per request, so there is nothing to
  // memoize — and the injected hook makes it uncallable outside a render, which
  // is exactly how the browser-mode tests mount it.
  "use no memo";

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
