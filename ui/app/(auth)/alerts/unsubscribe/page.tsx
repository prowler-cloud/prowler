import { notFound } from "next/navigation";

import {
  ALERT_PUBLIC_ACTIONS,
  AlertPublicAction,
} from "@/app/(auth)/alerts/_components/alert-public-action";

// NOT FOR THE MVP: recipient changes are managed inside the tenant product.
// Keep only if alert emails need public unsubscribe links.
interface AlertsUnsubscribePageProps {
  searchParams: Promise<{ token?: string }>;
}

export default async function AlertsUnsubscribePage({
  searchParams,
}: AlertsUnsubscribePageProps) {
  if (process.env.NEXT_PUBLIC_IS_CLOUD_ENV !== "true") {
    notFound();
  }

  const { token } = await searchParams;
  return (
    <AlertPublicAction
      action={ALERT_PUBLIC_ACTIONS.UNSUBSCRIBE}
      token={token ?? null}
      idleTitle="Unsubscribe from Prowler Cloud alerts"
      idleDescription="Click the button below to stop receiving alert digests at this email address. Pending notifications already in flight will be cancelled."
      ctaLabel="Unsubscribe"
    />
  );
}
