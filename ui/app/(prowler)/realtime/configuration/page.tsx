import { ArrowLeft, Radar } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";

import { isLighthouseConfigured } from "@/actions/lighthouse-v1";
import {
  getRealtimeCredential,
  getRealtimeFeed,
  getRealtimeFrameworks,
  getRealtimeNotificationTargets,
  getRealtimePolicy,
  getRealtimeRemediations,
  getRealtimeSetup,
} from "@/app/(prowler)/realtime/_actions";
import { ConfigurationSkeleton } from "@/app/(prowler)/realtime/_components/configuration/configuration-skeleton";
import { RealtimeConfiguration } from "@/app/(prowler)/realtime/_components/configuration/realtime-configuration";
import {
  REALTIME_VIEW,
  RealtimeAccountSelect,
} from "@/app/(prowler)/realtime/_components/dashboard/realtime-account-select";
import { RealtimeNoAccount } from "@/app/(prowler)/realtime/_components/dashboard/realtime-no-account";
import { RealtimePanelError } from "@/app/(prowler)/realtime/_components/shared/realtime-panel-error";
import {
  canManageRealtime,
  loadAwsProviders,
} from "@/app/(prowler)/realtime/_lib/load";
import {
  providerLabel,
  resolveProviderId,
} from "@/app/(prowler)/realtime/_lib/providers";
import {
  firstParam,
  REALTIME_PARAM,
  type RealtimeSearchParams,
  realtimeHref,
} from "@/app/(prowler)/realtime/_lib/routes";
import { initialOpenSection } from "@/app/(prowler)/realtime/_lib/setup";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { isCloud } from "@/lib/shared/env";

interface ConfigurationPageProps {
  searchParams: Promise<RealtimeSearchParams>;
}

export default async function RealtimeConfigurationPage({
  searchParams,
}: ConfigurationPageProps) {
  if (!isCloud()) notFound();
  const params = await searchParams;

  return (
    <ContentLayout title="Configuration" icon={<Radar />}>
      <Suspense fallback={<ConfigurationSkeleton />}>
        <ConfigurationContent searchParams={params} />
      </Suspense>
    </ContentLayout>
  );
}

async function ConfigurationContent({
  searchParams,
}: {
  searchParams: RealtimeSearchParams;
}) {
  const providersResult = await loadAwsProviders();
  if (!providersResult.ok) {
    return <RealtimePanelError failure={providersResult} />;
  }
  const { providers } = providersResult;
  if (providers.length === 0) return <RealtimeNoAccount />;

  const providerId = resolveProviderId(
    providers,
    firstParam(searchParams, REALTIME_PARAM.PROVIDER),
  ) as string;
  const provider = providers.find((item) => item.id === providerId);

  const [
    policy,
    feed,
    credential,
    setup,
    frameworks,
    targets,
    remediations,
    lighthouse,
    canManage,
  ] = await Promise.all([
    getRealtimePolicy(providerId),
    getRealtimeFeed(providerId),
    getRealtimeCredential(providerId),
    getRealtimeSetup(providerId),
    getRealtimeFrameworks(),
    getRealtimeNotificationTargets(),
    getRealtimeRemediations(providerId),
    isLighthouseConfigured(),
    canManageRealtime(),
  ]);

  // Without the policy, a save could overwrite what is stored.
  if (!policy.ok) return <RealtimePanelError failure={policy} />;
  const loadFailure = [
    feed,
    credential,
    setup,
    frameworks,
    targets,
    remediations,
  ].find((result) => !result.ok);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <RealtimeAccountSelect
          providers={providers}
          providerId={providerId}
          view={REALTIME_VIEW.CONFIGURATION}
        />
        <Button variant="outline" asChild>
          <Link href={realtimeHref(providerId)}>
            <ArrowLeft aria-hidden /> Back to the dashboard
          </Link>
        </Button>
      </div>
      {loadFailure && !loadFailure.ok && (
        <RealtimePanelError failure={loadFailure} />
      )}
      <RealtimeConfiguration
        key={providerId}
        providerId={providerId}
        accountLabel={provider ? providerLabel(provider) : providerId}
        canManage={canManage}
        policy={policy.data}
        feed={feed.ok ? feed.data : null}
        credential={credential.ok ? credential.data : null}
        setup={setup.ok ? setup.data : null}
        frameworks={frameworks.ok ? frameworks.data : []}
        targets={targets.ok ? targets.data : null}
        remediations={remediations.ok ? remediations.data : []}
        lighthouseConfigured={Boolean(lighthouse)}
        initialSection={initialOpenSection(
          setup.ok ? setup.data : null,
          firstParam(searchParams, REALTIME_PARAM.SECTION),
        )}
      />
    </div>
  );
}
