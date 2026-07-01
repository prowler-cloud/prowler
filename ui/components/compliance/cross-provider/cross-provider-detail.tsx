import type { CrossProviderComplianceOverviewAttributes } from "@/types/compliance";

import { CrossProviderDetailClient } from "./cross-provider-detail-client";

interface CrossProviderDetailProps {
  attributes: CrossProviderComplianceOverviewAttributes;
}

/**
 * Cross-provider compliance detail view.
 *
 * Server component shell — passes the API response straight through to
 * the client orchestrator. The orchestrator owns interactive state
 * (search term, status quick toggles, domain anchor scroll, drawer
 * selection) so every panel of the redesigned 3-pane header stays in
 * sync with the accordion below.
 */
export const CrossProviderDetail = ({
  attributes,
}: CrossProviderDetailProps) => {
  return <CrossProviderDetailClient attributes={attributes} />;
};
