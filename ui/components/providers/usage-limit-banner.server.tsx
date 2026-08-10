import { UsageLimitBanner } from "./usage-limit-banner";
import { shouldDisplayUsageLimitBanner } from "./usage-limit-banner.resolver";

interface UsageLimitBannerSSRProps {
  allowHide?: boolean;
  showBillingButton?: boolean;
  className?: string;
}

export const UsageLimitBannerSSR = async ({
  allowHide = false,
  showBillingButton = true,
  className,
}: UsageLimitBannerSSRProps) => {
  if (!(await shouldDisplayUsageLimitBanner())) return null;

  return (
    <div className={className}>
      <UsageLimitBanner
        allowHide={allowHide}
        showBillingButton={showBillingButton}
      />
    </div>
  );
};
