import { headers } from "next/headers";

import { MaintenanceView } from "./maintenance-view";

const DEFAULT_MESSAGE =
  "Prowler is currently undergoing scheduled maintenance. We will be back shortly.";

/**
 * Server Component: reads the ops-set message forwarded by the `proxy.ts`
 * maintenance gate as a request header (see `lib/maintenance.ts`
 * `maintenanceResponse`'s rewrite branch) and passes it down to the client
 * view. Falls back to `DEFAULT_MESSAGE` when the header is missing or empty
 * — e.g. when this route is hit directly in dev without going through the
 * gate.
 */
export default async function MaintenancePage() {
  const headerList = await headers();
  const message = headerList.get("x-maintenance-message") || DEFAULT_MESSAGE;

  return <MaintenanceView message={message} />;
}
