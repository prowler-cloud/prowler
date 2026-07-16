import { NoProvidersAdded } from "@/components/providers/no-providers-added";
import { ADD_PROVIDER_HREF } from "@/lib/providers-navigation";

import { NoProvidersConnected } from "./no-providers-connected";

interface ScansProvidersEmptyStateProps {
  thereIsNoProviders: boolean;
  /** Overrides the NoProvidersAdded container height so it can sit as a compact top hint. */
  containerClassName?: string;
}

export function ScansProvidersEmptyState({
  thereIsNoProviders,
  containerClassName,
}: ScansProvidersEmptyStateProps) {
  return thereIsNoProviders ? (
    <NoProvidersAdded
      action="link"
      href={ADD_PROVIDER_HREF}
      containerClassName={containerClassName}
    />
  ) : (
    <NoProvidersConnected />
  );
}
