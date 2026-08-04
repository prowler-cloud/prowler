import { listScanConfigurations } from "@/actions/scan-configurations";
import { ProvidersAccountsView } from "@/components/providers/providers-accounts-view";
import { isCloud } from "@/lib/shared/env";
import { SearchParamsProps } from "@/types";
import {
  SCAN_CONFIGURATION_LIST_STATUS,
  type ScanConfigurationListState,
} from "@/types/scan-configurations";
import {
  SCAN_SCHEDULE_CAPABILITY,
  type ScanSchedulingAccess,
} from "@/types/schedules";

import { loadProvidersAccountsViewData } from "./providers-page.utils";

interface ProvidersTabContentProps {
  searchParams: SearchParamsProps;
  /**
   * Injected so the chain it comes from stays out of this file. A thunk so it
   * resolves inside the `Promise.all` below, not ahead of it.
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

/**
 * A failed lookup must not read as "no lookup": `null` lets the consumers fall
 * back to the environment default, which is `ADVANCED` in Cloud — so an access
 * read that throws would hand out the very actions it gates. Deny them until it
 * recovers. `isScanLimitReached` stays false because no limit was observed; the
 * capability is what blocks.
 */
const SCAN_SCHEDULING_UNAVAILABLE: ScanSchedulingAccess = {
  capability: SCAN_SCHEDULE_CAPABILITY.BLOCKED,
  isScanLimitReached: false,
};

const resolveScanScheduling = async (
  load?: () => Promise<ScanSchedulingAccess>,
): Promise<ScanSchedulingAccess | null> => {
  // Only an omitted loader means "this deployment has no scheduling gate".
  if (!load) return null;

  try {
    return await load();
  } catch (error) {
    // Suspense does not catch errors: rejecting would hand the whole route
    // segment to the error boundary instead of degrading one affordance.
    console.error("Error loading scan scheduling access:", error);
    return SCAN_SCHEDULING_UNAVAILABLE;
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
