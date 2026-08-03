import { listScanConfigurations } from "@/actions/scan-configurations";
import { ProvidersAccountsView } from "@/components/providers/providers-accounts-view";
import { isCloud } from "@/lib/shared/env";
import { SearchParamsProps } from "@/types";
import {
  SCAN_CONFIGURATION_LIST_STATUS,
  type ScanConfigurationListState,
} from "@/types/scan-configurations";
import type { ScanSchedulingAccess } from "@/types/schedules";

import { loadProvidersAccountsViewData } from "./providers-page.utils";

interface ProvidersTabContentProps {
  searchParams: SearchParamsProps;
  /**
   * Injected so the billing chain it comes from in Prowler Cloud stays out of
   * this file. A thunk, not a value, so it resolves inside the `Promise.all`
   * below rather than ahead of the provider reads.
   */
  loadScanScheduling?: () => Promise<ScanSchedulingAccess>;
}

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

const resolveScanScheduling = async (
  load?: () => Promise<ScanSchedulingAccess>,
): Promise<ScanSchedulingAccess | null> => {
  if (!load) return null;

  try {
    return await load();
  } catch (error) {
    // Suspense does not catch errors: rejecting here would hand the whole route
    // segment to the error boundary instead of degrading one affordance.
    console.error("Error loading scan scheduling access:", error);
    return null;
  }
};

export const ProvidersTabContent = async ({
  searchParams,
  loadScanScheduling,
}: ProvidersTabContentProps) => {
  // The React Compiler (`reactCompiler: true`) otherwise instruments this as a
  // client component and injects `useMemoCache`, which needs a React dispatcher.
  // An async server component renders once per request, so there is nothing to
  // memoize — and the injected hook makes it uncallable outside a render, which
  // is exactly how the browser-mode tests mount it.
  "use no memo";

  const isCloudEnvironment = isCloud();
  const [providersView, scanConfigsState, scanScheduling] = await Promise.all([
    loadProvidersAccountsViewData({
      searchParams,
      isCloud: isCloudEnvironment,
    }),
    loadScanConfigs(isCloudEnvironment),
    resolveScanScheduling(loadScanScheduling),
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
      scanScheduleCapability={scanScheduling?.capability}
      isScanLimitReached={scanScheduling?.isScanLimitReached ?? false}
      scanConfigs={scanConfigsState.data}
      scanConfigStatus={scanConfigsState.status}
    />
  );
};
