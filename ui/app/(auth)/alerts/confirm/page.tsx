import { notFound } from "next/navigation";

import {
  ALERT_PUBLIC_ACTIONS,
  AlertPublicAction,
} from "@/app/(auth)/alerts/_components/alert-public-action";
import { isAlertsEnabled } from "@/app/(prowler)/alerts/_lib/env";

// NOT FOR THE MVP: tenant-owned recipients are treated as already confirmed.
// Keep only if we reintroduce public recipient consent links.
interface AlertsConfirmPageProps {
  searchParams: Promise<{ token?: string }>;
}

export default async function AlertsConfirmPage({
  searchParams,
}: AlertsConfirmPageProps) {
  if (!isAlertsEnabled()) {
    notFound();
  }

  const { token } = await searchParams;
  return (
    <AlertPublicAction
      action={ALERT_PUBLIC_ACTIONS.CONFIRM}
      token={token ?? null}
      idleTitle="Confirm your Prowler Cloud alerts subscription"
      idleDescription="Click the button below to confirm this email address. After confirming, alert digests for the alerts your team picked you for will start arriving here."
      ctaLabel="Confirm subscription"
    />
  );
}
