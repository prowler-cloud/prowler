import { useCloudUpgradeStore } from "@/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

/** Wraps report downloads so subscription-only tenants get the paid plan upgrade instead. */
export const useReportDownload = (subscriptionOnly = false) => {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (download: () => void | Promise<void>) => {
    if (subscriptionOnly) {
      openCloudUpgrade(PAID_PLAN_UPGRADE_FEATURE.REPORT_DOWNLOAD);
      return;
    }

    return download();
  };
};
