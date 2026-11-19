"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Controller, useForm, useFormState, useWatch } from "react-hook-form";

import { saveRealtimeCostSettings } from "@/app/(prowler)/realtime/_actions";
import {
  type CostFormValues,
  costFormDefaults,
  toNumber,
} from "@/app/(prowler)/realtime/_lib/configuration-forms";
import { realtimeCostAnomalySchema } from "@/app/(prowler)/realtime/_lib/policy-schema";
import { costSummary } from "@/app/(prowler)/realtime/_lib/setup";
import {
  COST_CLOUDFORMATION,
  COST_TERRAFORM,
} from "@/app/(prowler)/realtime/_lib/templates";
import {
  REALTIME_COST_DELTA_RANGE,
  REALTIME_COST_RATIO_RANGE,
  type RealtimePolicy,
} from "@/app/(prowler)/realtime/_types";
import {
  Alert,
  AlertDescription,
  Field,
  FieldError,
  FieldLabel,
  Input,
  Switch,
} from "@/components/shadcn";
import { toast } from "@/components/shadcn/toast";

import { ConfigSectionCard, SectionFooter } from "./config-section-card";
import { reportSaveFailure, type SectionBaseProps } from "./section-props";
import { TemplateGuide } from "./template-guide";

const COST_FIELDS = [
  "cost_anomaly_enabled",
  "cost_anomaly_min_ratio",
  "cost_anomaly_min_delta",
] as const;

interface CostSectionProps extends SectionBaseProps {
  policy: RealtimePolicy | null;
}

export function CostSection(props: CostSectionProps) {
  return (
    <ConfigSectionCard
      id="cost"
      number={props.number}
      title="Cost anomalies"
      description="Flag a service whose daily spend jumps well above its usual level."
      summary={costSummary(props.policy)}
      state={props.state}
      required={props.required}
      open={props.open}
      onOpen={props.onOpen}
      lockedReason={props.policy ? undefined : "Save “What to enforce” first."}
    >
      {props.policy && <CostForm {...props} policy={props.policy} />}
    </ConfigSectionCard>
  );
}

function CostForm({
  policy,
  providerId,
  canManage,
  onClose,
  onSaved,
}: CostSectionProps & { policy: RealtimePolicy }) {
  const form = useForm<CostFormValues>({
    resolver: zodResolver(realtimeCostAnomalySchema),
    defaultValues: costFormDefaults(policy),
  });
  const enabled = useWatch({
    control: form.control,
    name: "cost_anomaly_enabled",
  });
  const { errors, isSubmitting } = useFormState({ control: form.control });

  const submit = async (values: CostFormValues) => {
    const result = await saveRealtimeCostSettings({
      providerId,
      policyId: policy.id,
      settings: values,
    });
    if (!result.ok) {
      reportSaveFailure(
        result,
        form.setError,
        COST_FIELDS,
        "Cost settings not saved",
      );
      return;
    }
    toast({ title: "Cost anomaly settings saved" });
    onSaved();
  };

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate>
      <fieldset
        disabled={!canManage}
        className="flex flex-col gap-5 px-[18px] py-4"
      >
        <legend className="sr-only">Cost anomalies</legend>
        <Controller
          control={form.control}
          name="cost_anomaly_enabled"
          render={({ field }) => (
            <div className="flex items-center justify-between gap-4">
              <label
                htmlFor="cost-enabled"
                className="text-text-neutral-primary text-sm font-medium"
              >
                Detect cost anomalies for this account
              </label>
              <Switch
                id="cost-enabled"
                checked={field.value}
                onCheckedChange={field.onChange}
              />
            </div>
          )}
        />
        {enabled && (
          <>
            <Alert variant="warning">
              <AlertDescription>
                AWS bills each Cost Explorer request. Prowler reads it about
                every 6 hours.
              </AlertDescription>
            </Alert>
            <TemplateGuide
              cloudformation={COST_CLOUDFORMATION}
              terraform={COST_TERRAFORM}
              steps={[
                "Deploy the template once in this AWS account. It lets the ProwlerScan role read Cost Explorer (ce:GetCostAndUsage) and nothing else. If your scan role has another name, set ProwlerScanRoleName (prowler_scan_role_name in Terraform) to it.",
                "Save below. Costs show up after Prowler's next Cost Explorer read.",
              ]}
            />
          </>
        )}
        <div className="grid gap-4 md:grid-cols-2">
          <Controller
            control={form.control}
            name="cost_anomaly_min_ratio"
            render={({ field }) => (
              <Field>
                <FieldLabel htmlFor="cost-ratio">Minimum ratio</FieldLabel>
                <Input
                  id="cost-ratio"
                  type="number"
                  inputMode="decimal"
                  step={0.1}
                  min={REALTIME_COST_RATIO_RANGE.min}
                  max={REALTIME_COST_RATIO_RANGE.max}
                  disabled={!enabled}
                  aria-invalid={Boolean(errors.cost_anomaly_min_ratio)}
                  value={Number.isNaN(field.value) ? "" : field.value}
                  onChange={(event) =>
                    field.onChange(toNumber(event.target.value))
                  }
                  onBlur={field.onBlur}
                />
                <span className="text-text-neutral-tertiary text-xs">
                  Today against the 14-day daily average, for example 2 for
                  twice as much.
                </span>
                {errors.cost_anomaly_min_ratio && (
                  <FieldError>
                    {errors.cost_anomaly_min_ratio.message}
                  </FieldError>
                )}
              </Field>
            )}
          />
          <Controller
            control={form.control}
            name="cost_anomaly_min_delta"
            render={({ field }) => (
              <Field>
                <FieldLabel htmlFor="cost-delta">
                  Minimum increase (dollars)
                </FieldLabel>
                <Input
                  id="cost-delta"
                  type="number"
                  inputMode="decimal"
                  step={0.5}
                  min={REALTIME_COST_DELTA_RANGE.min}
                  max={REALTIME_COST_DELTA_RANGE.max}
                  disabled={!enabled}
                  aria-invalid={Boolean(errors.cost_anomaly_min_delta)}
                  value={Number.isNaN(field.value) ? "" : field.value}
                  onChange={(event) =>
                    field.onChange(toNumber(event.target.value))
                  }
                  onBlur={field.onBlur}
                />
                <span className="text-text-neutral-tertiary text-xs">
                  Ignores small services whose spend doubles by a few cents.
                </span>
                {errors.cost_anomaly_min_delta && (
                  <FieldError>
                    {errors.cost_anomaly_min_delta.message}
                  </FieldError>
                )}
              </Field>
            )}
          />
        </div>
      </fieldset>
      <SectionFooter
        onCancel={onClose}
        submitLabel="Save"
        pending={isSubmitting}
        disabled={!canManage}
      />
    </form>
  );
}
