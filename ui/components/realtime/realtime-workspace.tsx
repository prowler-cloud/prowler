"use client";

import Link from "next/link";
import { useState } from "react";

import { getRealtimePolicy } from "@/actions/realtime";
import { DemoBanner, DemoProvider } from "@/components/realtime/demo-context";
import { FindingsTab } from "@/components/realtime/findings-tab";
import { OverviewTab } from "@/components/realtime/overview-tab";
import {
  ProviderSelect,
  syncProviderToUrl,
} from "@/components/realtime/provider-select";
import {
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { RemediationTab } from "@/components/realtime/remediation-tab";
import { StatusStatementCard } from "@/components/realtime/status-statement-card";
import { StreamTab } from "@/components/realtime/stream-tab";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn/tabs/tabs";
import { useAuth } from "@/hooks/use-auth";
import { isRealtimeDemoMode } from "@/lib/realtime/demo";
import { settingsHref } from "@/lib/realtime/display";
import {
  providerLabel,
  type RealtimeProviderOption,
  resolveProviderId,
} from "@/lib/realtime/providers";
import { REALTIME_TAB, type RealtimeTab } from "@/types/realtime";

export { providerLabel, resolveProviderId };
export type { RealtimeProviderOption };

interface RealtimeWorkspaceProps {
  providers: RealtimeProviderOption[];
  initialProviderId?: string;
  initialTab?: string;
}

const TAB_LABELS: Array<[RealtimeTab, string]> = [
  [REALTIME_TAB.OVERVIEW, "Overview"],
  [REALTIME_TAB.STREAM, "Live stream"],
  [REALTIME_TAB.FINDINGS, "Findings & signals"],
  [REALTIME_TAB.REMEDIATION, "Remediation"],
  [REALTIME_TAB.STATUS, "Status"],
];

export const isRealtimeTab = (value: unknown): value is RealtimeTab =>
  TAB_LABELS.some(([tab]) => tab === value);

export function RealtimeWorkspace({
  providers,
  initialProviderId,
  initialTab,
}: RealtimeWorkspaceProps) {
  const { permissions } = useAuth();
  const canManage = permissions.manage_prowler_realtime === true;
  const [providerId, setProviderId] = useState(
    resolveProviderId(providers, initialProviderId),
  );
  const [tab, setTab] = useState<RealtimeTab>(
    isRealtimeTab(initialTab) ? initialTab : REALTIME_TAB.OVERVIEW,
  );

  // Whether the account is set up decides between its data and the sample.
  const policy = useRealtimeResource(
    () => getRealtimePolicy(providerId ?? ""),
    `policy:${providerId ?? ""}`,
    { enabled: Boolean(providerId) },
  );

  // The URL carries the selection so a view can be shared and survives a reload.
  const syncUrl = syncProviderToUrl;

  const demo = isRealtimeDemoMode({ providerId, policy: policy.data });
  const checking = Boolean(providerId) && (policy.loading || !policy.result);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        {providerId ? (
          <ProviderSelect
            providers={providers}
            value={providerId}
            onChange={(value) => {
              setProviderId(value);
              syncUrl({ provider: value });
            }}
          />
        ) : (
          <p className="text-text-neutral-secondary text-sm">
            No AWS account is connected yet.{" "}
            <Link
              href="/providers"
              className="text-button-tertiary underline underline-offset-4"
            >
              Go to Providers
            </Link>
          </p>
        )}
        <div className="flex items-center gap-3">
          {!canManage && <Badge variant="tag">Read only</Badge>}
          {providerId && (
            <Button asChild variant="outline" size="sm">
              <Link href={settingsHref(providerId)}>Configure</Link>
            </Button>
          )}
        </div>
      </div>

      {checking ? (
        <PanelLoading label="Checking the account" />
      ) : policy.failure ? (
        <PanelFailure
          failure={policy.failure}
          onRetry={policy.reload}
          subject="the account"
        />
      ) : (
        <DemoProvider key={providerId} demo={demo}>
          {demo && <DemoBanner providerId={providerId} />}
          <Tabs
            value={tab}
            onValueChange={(value) => {
              setTab(value as RealtimeTab);
              syncUrl({ tab: value });
            }}
          >
            <TabsList className="overflow-x-auto">
              {TAB_LABELS.map(([value, label]) => (
                <TabsTrigger key={value} value={value}>
                  {label}
                </TabsTrigger>
              ))}
            </TabsList>

            <TabsContent value={REALTIME_TAB.OVERVIEW} className="pt-4">
              <OverviewTab providerId={providerId ?? ""} demo={demo} />
            </TabsContent>
            <TabsContent value={REALTIME_TAB.STREAM} className="pt-4">
              <StreamTab providerId={providerId ?? ""} demo={demo} />
            </TabsContent>
            <TabsContent value={REALTIME_TAB.FINDINGS} className="pt-4">
              <FindingsTab providerId={providerId ?? ""} demo={demo} />
            </TabsContent>
            <TabsContent value={REALTIME_TAB.REMEDIATION} className="pt-4">
              <RemediationTab
                providerId={providerId ?? ""}
                canManage={canManage}
                demo={demo}
              />
            </TabsContent>
            <TabsContent value={REALTIME_TAB.STATUS} className="pt-4">
              <StatusStatementCard providerId={providerId ?? ""} demo={demo} />
            </TabsContent>
          </Tabs>
        </DemoProvider>
      )}
    </div>
  );
}
