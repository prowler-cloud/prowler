import Link from "next/link";

import { AuthLayout } from "@/components/auth/oss/auth-layout";
import { Button } from "@/components/shadcn";

import { unsubscribeAlertRecipient } from "./unsubscribe-alert-recipient";

interface AlertsUnsubscribePageProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

const getParamValue = (
  params: Awaited<AlertsUnsubscribePageProps["searchParams"]>,
  key: string,
): string | undefined => {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
};

export default async function AlertsUnsubscribePage({
  searchParams,
}: AlertsUnsubscribePageProps) {
  const resolvedSearchParams = await searchParams;
  const token = getParamValue(resolvedSearchParams, "token");
  const result = await unsubscribeAlertRecipient(token);
  const title = result.ok ? "Unsubscribed" : "Subscription link";

  return (
    <AuthLayout title={title}>
      <div className="flex flex-col gap-4">
        <p className="text-text-neutral-secondary text-sm leading-6">
          {result.message}
        </p>
        <Button variant="outline" className="w-full" asChild>
          <Link href="/">Continue to Prowler</Link>
        </Button>
      </div>
    </AuthLayout>
  );
}
