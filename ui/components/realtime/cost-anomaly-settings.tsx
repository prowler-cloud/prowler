"use client";

import Link from "next/link";
import { useId, useState } from "react";

import {
  getRealtimePolicy,
  saveRealtimeCostSettings,
} from "@/actions/realtime";
import {
  ProviderSelect,
  syncProviderToUrl,
} from "@/components/realtime/provider-select";
import { NoAwsProvider } from "@/components/realtime/realtime-settings";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import { Switch } from "@/components/shadcn/switch/switch";
import { useToast } from "@/components/shadcn/toast";
import { useAuth } from "@/hooks/use-auth";
import { settingsHref } from "@/lib/realtime/display";
import {
  DEFAULT_REALTIME_POLICY,
  realtimeCostAnomalySchema,
} from "@/lib/realtime/policy-schema";
import {
  type RealtimeProviderOption,
  resolveProviderId,
} from "@/lib/realtime/providers";
import {
  REALTIME_COST_DELTA_RANGE,
  REALTIME_COST_RATIO_RANGE,
  type RealtimePolicy,
} from "@/types/realtime";

interface CostAnomalyFormProps {
  providerId: string;
  policy: RealtimePolicy | null;
  canManage: boolean;
  onSaved: (policy: RealtimePolicy) => void;
}

/** The text of a number input to a number; NaN when it is empty or not a number. */
const toNumber = (text: string) => (text.trim() === "" ? NaN : Number(text));

export function CostAnomalyForm({
  providerId,
  policy,
  canManage,
  onSaved,
}: CostAnomalyFormProps) {
  const { toast } = useToast();
  const id = useId();
  const initial = policy ?? DEFAULT_REALTIME_POLICY;
  const [enabled, setEnabled] = useState(initial.cost_anomaly_enabled);
  const [ratio, setRatio] = useState(String(initial.cost_anomaly_min_ratio));
  const [delta, setDelta] = useState(String(initial.cost_anomaly_min_delta));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  const disabled = !canManage || saving;

  const submit = async () => {
    const parsed = realtimeCostAnomalySchema.safeParse({
      cost_anomaly_enabled: enabled,
      cost_anomaly_min_ratio: toNumber(ratio),
      cost_anomaly_min_delta: toNumber(delta),
    });
    if (!parsed.success) {
      const found: Record<string, string> = {};
      parsed.error.issues.forEach((issue) => {
        const field = String(issue.path[0] ?? "form");
        if (!found[field]) found[field] = issue.message;
      });
      setErrors(found);
      return;
    }
    setErrors({});
    setSaving(true);
    const result = await saveRealtimeCostSettings({
      providerId,
      policyId: policy?.id,
      settings: parsed.data,
    });
    setSaving(false);
    if (result.ok) {
      onSaved(result.data);
      toast({
        title: enabled
          ? "Cost anomalies are on"
          : "Cost anomaly settings saved",
      });
    } else {
      setErrors(result.fieldErrors ?? {});
      toast({
        variant: "destructive",
        title:
          result.status === 403
            ? "You cannot change these settings"
            : "Could not save the settings",
        description:
          result.status === 403
            ? "Changing them needs the Manage Realtime permission."
            : result.error,
      });
    }
  };

  return (
    <form
      noValidate
      className="flex flex-col gap-6"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      {!canManage && (
        <Alert variant="info">
          <AlertTitle>Read only</AlertTitle>
          <AlertDescription>
            <p>
              Your role can see these settings but not change them. Changing
              them needs the Manage Realtime permission.
            </p>
          </AlertDescription>
        </Alert>
      )}

      <div className="flex items-start gap-3">
        <Switch
          id={`${id}-enabled`}
          checked={enabled}
          disabled={disabled}
          aria-describedby={`${id}-enabled-description`}
          onCheckedChange={setEnabled}
        />
        <div className="flex flex-col gap-0.5">
          <label
            htmlFor={`${id}-enabled`}
            className="text-text-neutral-primary text-sm font-medium"
          >
            Detect cost anomalies for this account
          </label>
          <p
            id={`${id}-enabled-description`}
            className="text-text-neutral-tertiary max-w-prose text-xs"
          >
            A sudden jump in spend in one service often means a resource is
            being used by someone else. When it is on, findings in that service
            rank higher and the dashboard shows the cost.
          </p>
        </div>
      </div>

      <Alert variant="warning">
        <AlertTitle>AWS Cost Explorer is billed per request</AlertTitle>
        <AlertDescription>
          <p>
            Once on, Prowler Realtime asks AWS Cost Explorer for this
            account&apos;s daily cost about every 6 hours, and AWS charges for
            each request. It is off until you enable it here, and nothing is
            requested while it is off.
          </p>
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Field>
          <FieldLabel htmlFor={`${id}-ratio`}>Minimum ratio</FieldLabel>
          <Input
            id={`${id}-ratio`}
            type="number"
            inputMode="decimal"
            step="0.1"
            min={REALTIME_COST_RATIO_RANGE.min}
            max={REALTIME_COST_RATIO_RANGE.max}
            value={ratio}
            disabled={disabled}
            aria-invalid={Boolean(errors.cost_anomaly_min_ratio)}
            aria-describedby={`${id}-ratio-hint`}
            onChange={(event) => setRatio(event.target.value)}
          />
          <p
            id={`${id}-ratio-hint`}
            className="text-text-neutral-tertiary text-xs"
          >
            An anomaly is today&apos;s spend being this many times the trailing
            baseline. From {REALTIME_COST_RATIO_RANGE.min} to{" "}
            {REALTIME_COST_RATIO_RANGE.max}; 2 means double.
          </p>
          {errors.cost_anomaly_min_ratio && (
            <FieldError>{errors.cost_anomaly_min_ratio}</FieldError>
          )}
        </Field>
        <Field>
          <FieldLabel htmlFor={`${id}-delta`}>
            Minimum increase (dollars)
          </FieldLabel>
          <Input
            id={`${id}-delta`}
            type="number"
            inputMode="decimal"
            step="0.5"
            min={REALTIME_COST_DELTA_RANGE.min}
            max={REALTIME_COST_DELTA_RANGE.max}
            value={delta}
            disabled={disabled}
            aria-invalid={Boolean(errors.cost_anomaly_min_delta)}
            aria-describedby={`${id}-delta-hint`}
            onChange={(event) => setDelta(event.target.value)}
          />
          <p
            id={`${id}-delta-hint`}
            className="text-text-neutral-tertiary text-xs"
          >
            The spend must also grow by at least this much, so a cheap service
            doubling from a few cents is not reported. From{" "}
            {REALTIME_COST_DELTA_RANGE.min} to {REALTIME_COST_DELTA_RANGE.max}.
          </p>
          {errors.cost_anomaly_min_delta && (
            <FieldError>{errors.cost_anomaly_min_delta}</FieldError>
          )}
        </Field>
      </div>

      {!policy && (
        <p className="text-text-neutral-tertiary text-xs">
          This account has no policy yet. Saving creates one with the safe
          defaults: detection stays off and nothing is changed in the account.
          You can set it up in the{" "}
          <Link
            href={settingsHref(providerId)}
            className="text-button-tertiary underline underline-offset-4"
          >
            Realtime settings
          </Link>
          .
        </p>
      )}

      {canManage && (
        <div className="flex items-center gap-3">
          <Button type="submit" disabled={saving}>
            {saving ? "Saving…" : "Save cost anomaly settings"}
          </Button>
          {Object.keys(errors).length > 0 && (
            <span role="alert" className="text-text-error-primary text-sm">
              Fix the highlighted fields and try again.
            </span>
          )}
        </div>
      )}
    </form>
  );
}

function CostSettingsBody({
  providerId,
  canManage,
}: {
  providerId: string;
  canManage: boolean;
}) {
  const policy = useRealtimeResource(
    () => getRealtimePolicy(providerId),
    `policy:${providerId}`,
  );

  return (
    <div className="flex max-w-3xl flex-col gap-4">
      <RealtimeSection
        title="Cost anomalies"
        description="Turn the cost signal on per AWS account and choose how big a jump counts as an anomaly."
        action={
          policy.data?.cost_anomaly_enabled ? (
            <Badge variant="success">On</Badge>
          ) : (
            <Badge variant="tag">Off</Badge>
          )
        }
      >
        {policy.loading ? (
          <PanelLoading label="Loading the settings" />
        ) : policy.failure ? (
          <PanelFailure
            failure={policy.failure}
            onRetry={policy.reload}
            subject="the settings"
          />
        ) : (
          <CostAnomalyForm
            key={policy.data?.id ?? "new"}
            providerId={providerId}
            policy={policy.data ?? null}
            canManage={canManage}
            onSaved={policy.setData}
          />
        )}
      </RealtimeSection>
    </div>
  );
}

export function CostAnomalySettings({
  providers,
  initialProviderId,
}: {
  providers: RealtimeProviderOption[];
  initialProviderId?: string;
}) {
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
            <Link href={`/realtime?provider=${encodeURIComponent(providerId)}`}>
              Back to the dashboard
            </Link>
          </Button>
        </div>
      </div>
      <CostSettingsBody
        key={providerId}
        providerId={providerId}
        canManage={canManage}
      />
    </div>
  );
}
