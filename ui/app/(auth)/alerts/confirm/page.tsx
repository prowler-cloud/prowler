import Link from "next/link";

import { AuthLayout } from "@/components/auth/oss/auth-layout";
import { Button } from "@/components/shadcn";

import { confirmAlertRecipient } from "./confirm-alert-recipient";

interface AlertsConfirmPageProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

const getParamValue = (
  params: Awaited<AlertsConfirmPageProps["searchParams"]>,
  key: string,
): string | undefined => {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
};

export default async function AlertsConfirmPage({
  searchParams,
}: AlertsConfirmPageProps) {
  const resolvedSearchParams = await searchParams;
  const token = getParamValue(resolvedSearchParams, "token");
  const result = await confirmAlertRecipient(token);
  const title = result.ok ? "Subscription confirmed" : "Subscription link";

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
