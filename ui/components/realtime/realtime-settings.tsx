"use client";

import Link from "next/link";
import { useState } from "react";

import {
  getRealtimeCredential,
  getRealtimeFrameworks,
  getRealtimePolicy,
} from "@/actions/realtime";
import { CredentialsForm } from "@/components/realtime/credentials-form";
import { FeedSetupPanel } from "@/components/realtime/feed-setup-panel";
import { FrameworkBadges } from "@/components/realtime/framework-badges";
import { AlertsSection } from "@/components/realtime/notifications-section";
import { PolicyForm } from "@/components/realtime/policy-form";
import {
  ProviderSelect,
  syncProviderToUrl,
} from "@/components/realtime/provider-select";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelEmpty,
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { useAuth } from "@/hooks/use-auth";
import {
  REALTIME_COST_SETTINGS_PATH,
  settingsHref,
} from "@/lib/realtime/display";
import {
  type RealtimeProviderOption,
  resolveProviderId,
} from "@/lib/realtime/providers";

interface RealtimeSettingsProps {
  providers: RealtimeProviderOption[];
  initialProviderId?: string;
  /** Whether a connected Lighthouse AI configuration exists; undefined when unknown. */
  lighthouseConfigured?: boolean;
}

export function NoAwsProvider() {
  return (
    <PanelEmpty
      title="Connect an AWS account first"
      description="Prowler Realtime Detection and Remediation works on AWS accounts. Add an AWS provider and it will appear here."
    >
      <Link
        href="/providers"
        className="text-button-tertiary text-sm underline underline-offset-4"
      >
        Go to Providers
      </Link>
    </PanelEmpty>
  );
}

/** Settings for one AWS account: policy, remediation credentials and the event feed. */
export function RealtimeSettings({
  providers,
  initialProviderId,
  lighthouseConfigured,
}: RealtimeSettingsProps) {
  const { permissions } = useAuth();
  const canManage = permissions.manage_prowler_realtime === true;
  const [providerId, setProviderId] = useState(
    resolveProviderId(providers, initialProviderId),
  );

  if (!providerId) return <NoAwsProvider />;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <ProviderSelect
          providers={providers}
          value={providerId}
          onChange={(value) => {
            setProviderId(value);
            syncProviderToUrl({ provider: value });
          }}
        />
        <div className="flex items-center gap-3">
          {!canManage && <Badge variant="tag">Read only</Badge>}
          <Button asChild variant="outline" size="sm">
            <Link href={settingsHref(providerId, REALTIME_COST_SETTINGS_PATH)}>
              Cost anomalies
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link href={`/realtime?provider=${encodeURIComponent(providerId)}`}>
              Back to the dashboard
            </Link>
          </Button>
        </div>
      </div>

      <SettingsBody
        key={providerId}
        providerId={providerId}
        canManage={canManage}
        lighthouseConfigured={lighthouseConfigured}
      />
    </div>
  );
}

function SettingsBody({
  providerId,
  canManage,
  lighthouseConfigured,
}: {
  providerId: string;
  canManage: boolean;
  lighthouseConfigured?: boolean;
}) {
  const policy = useRealtimeResource(
    () => getRealtimePolicy(providerId),
    `policy:${providerId}`,
  );
  const credential = useRealtimeResource(
    () => getRealtimeCredential(providerId),
    `credential:${providerId}`,
  );
  const frameworks = useRealtimeResource(
    () => getRealtimeFrameworks(),
    "frameworks",
  );
  const catalog = frameworks.data ?? [];

  return (
    <div className="flex max-w-4xl flex-col gap-10">
      <RealtimeSection
        title="Policy"
        description="How Prowler Realtime responds for this AWS account. The defaults are the safe ones: propose changes for review, change nothing in the account."
      >
        {policy.loading ? (
          <PanelLoading label="Loading the policy" />
        ) : policy.failure ? (
          <PanelFailure
            failure={policy.failure}
            onRetry={policy.reload}
            subject="the policy"
          />
        ) : (
          <div className="flex flex-col gap-6">
            <div className="flex flex-col gap-2">
              <span className="text-text-neutral-secondary text-xs font-medium">
                Enforced compliance frameworks
              </span>
              <FrameworkBadges
                frameworks={policy.data?.frameworks ?? []}
                catalog={catalog}
              />
            </div>
            <PolicyForm
              // A saved policy gets a new id and remounts the form on first save.
              key={policy.data?.id ?? "new"}
              providerId={providerId}
              policy={policy.data ?? null}
              canManage={canManage}
              onSaved={policy.setData}
              frameworkCatalog={catalog}
              lighthouseConfigured={lighthouseConfigured}
            />
          </div>
        )}
      </RealtimeSection>

      {!policy.loading && !policy.failure && (
        <AlertsSection
          key={policy.data?.id ?? "new"}
          providerId={providerId}
          policy={policy.data ?? null}
          canManage={canManage}
          onSaved={policy.setData}
        />
      )}

      {credential.loading ? (
        <PanelLoading label="Loading credentials" />
      ) : credential.failure ? (
        <PanelFailure
          failure={credential.failure}
          onRetry={credential.reload}
          subject="the credentials"
        />
      ) : (
        <CredentialsForm
          providerId={providerId}
          credential={credential.data ?? null}
          canManage={canManage}
          onChanged={(next) => credential.setData(next)}
        />
      )}

      <FeedSetupPanel providerId={providerId} canManage={canManage} />
    </div>
  );
}
