import { NoProvidersAdded } from "@/components/providers/no-providers-added";
import { ADD_PROVIDER_HREF } from "@/lib/providers-navigation";

import { NoProvidersConnected } from "./no-providers-connected";

interface ScansProvidersEmptyStateProps {
  thereIsNoProviders: boolean;
}

export function ScansProvidersEmptyState({
  thereIsNoProviders,
}: ScansProvidersEmptyStateProps) {
  return (
    <>
      {thereIsNoProviders ? (
        <NoProvidersAdded action="link" href={ADD_PROVIDER_HREF} />
      ) : (
        <NoProvidersConnected />
      )}
    </>
  );
}
