import { CustomBanner } from "@/components/shadcn/custom/custom-banner";
import { ADD_PROVIDER_HREF } from "@/lib/providers-navigation";
import { isCloud } from "@/lib/shared/env";

interface ScansProvidersEmptyStateProps {
  thereIsNoProviders: boolean;
}

export function ScansProvidersEmptyState({
  thereIsNoProviders,
}: ScansProvidersEmptyStateProps) {
  // Imported scans are Cloud-only, so only Cloud mentions that they stay visible.
  const disconnectedMessage = isCloud()
    ? "None of your providers are connected yet. Connect one to launch on-demand scans — imported scans still appear below."
    : "None of your providers are connected yet. Connect one to launch on-demand scans.";

  return thereIsNoProviders ? (
    <CustomBanner
      title="No Providers Configured"
      message="No providers have been configured. Start by setting up a provider."
      buttonLabel="Add a Provider"
      buttonLink={ADD_PROVIDER_HREF}
    />
  ) : (
    <CustomBanner
      title="No Connected Providers"
      message={disconnectedMessage}
      buttonLabel="Review Providers"
      buttonLink="/providers"
    />
  );
}
