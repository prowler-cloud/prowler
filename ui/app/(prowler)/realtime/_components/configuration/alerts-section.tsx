"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import {
  Controller,
  type Path,
  useForm,
  useFormState,
  useWatch,
} from "react-hook-form";

import { saveRealtimeNotifications } from "@/app/(prowler)/realtime/_actions";
import {
  ALERTS_PATH,
  isSelectableRecipient,
  recipientStatusLabel,
  SLACK_INTEGRATIONS_PATH,
  toggleId,
} from "@/app/(prowler)/realtime/_lib/notifications";
import {
  DEFAULT_REALTIME_NOTIFICATIONS,
  realtimeNotificationsSchema,
} from "@/app/(prowler)/realtime/_lib/policy-schema";
import { alertsSummary } from "@/app/(prowler)/realtime/_lib/setup";
import {
  REALTIME_MIN_SEVERITY,
  type RealtimeNotifications,
  type RealtimeNotificationTargets,
  type RealtimePolicy,
} from "@/app/(prowler)/realtime/_types";
import {
  Badge,
  Button,
  Checkbox,
  Field,
  FieldError,
  FieldLabel,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
} from "@/components/shadcn";
import { toast } from "@/components/shadcn/toast";

import { ConfigSectionCard, SectionFooter } from "./config-section-card";
import { reportSaveFailure, type SectionBaseProps } from "./section-props";

const SEVERITY_OPTIONS = [
  { value: REALTIME_MIN_SEVERITY.LOW, label: "Low and above" },
  { value: REALTIME_MIN_SEVERITY.MEDIUM, label: "Medium and above" },
  { value: REALTIME_MIN_SEVERITY.HIGH, label: "High and above" },
  { value: REALTIME_MIN_SEVERITY.CRITICAL, label: "Critical only" },
] as const;

interface AlertsSectionProps extends SectionBaseProps {
  policy: RealtimePolicy | null;
  targets: RealtimeNotificationTargets | null;
}

export function AlertsSection(props: AlertsSectionProps) {
  return (
    <ConfigSectionCard
      id="alerts"
      number={props.number}
      title="Alerts"
      description="Where a confirmed violation, and the result of its fix, is sent."
      summary={alertsSummary(
        props.policy?.notifications ?? null,
        props.targets,
      )}
      state={props.state}
      required={props.required}
      open={props.open}
      onOpen={props.onOpen}
      lockedReason={props.policy ? undefined : "Save “What to enforce” first."}
    >
      {props.policy && <AlertsForm {...props} policy={props.policy} />}
    </ConfigSectionCard>
  );
}

interface ChannelToggleProps {
  id: string;
  label: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}

function ChannelToggle({
  id,
  label,
  checked,
  onCheckedChange,
}: ChannelToggleProps) {
  return (
    <div className="flex items-center justify-between gap-4">
      <label
        htmlFor={id}
        className="text-text-neutral-primary text-sm font-medium"
      >
        {label}
      </label>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}

function AlertsForm({
  policy,
  targets,
  providerId,
  canManage,
  onClose,
  onSaved,
}: AlertsSectionProps & { policy: RealtimePolicy }) {
  const form = useForm<RealtimeNotifications>({
    resolver: zodResolver(realtimeNotificationsSchema),
    defaultValues: policy.notifications ?? DEFAULT_REALTIME_NOTIFICATIONS,
  });
  const [slackOn, emailOn] = useWatch({
    control: form.control,
    name: ["slack.enabled", "email.enabled"],
  });
  const { errors, isSubmitting } = useFormState({ control: form.control });
  const slackTargets = targets?.slack ?? [];
  const emailTargets = targets?.email ?? [];

  const submit = async (values: RealtimeNotifications) => {
    const result = await saveRealtimeNotifications({
      providerId,
      policyId: policy.id,
      notifications: values,
    });
    if (!result.ok) {
      const failure = {
        ...result,
        // The API reports the whole attribute; show it under the form.
        fieldErrors: result.fieldErrors?.notifications
          ? { "root.server": result.fieldErrors.notifications }
          : result.fieldErrors,
      };
      reportSaveFailure(
        failure,
        form.setError,
        ["slack", "email", "root.server"] as Path<RealtimeNotifications>[],
        "Alerts not saved",
      );
      return;
    }
    toast({ title: "Alerts saved" });
    onSaved();
  };

  return (
    <form onSubmit={form.handleSubmit(submit)} noValidate>
      <fieldset
        disabled={!canManage}
        className="flex flex-col gap-6 px-[18px] py-4"
      >
        <legend className="sr-only">Alerts</legend>

        <div className="flex flex-col gap-3">
          <Controller
            control={form.control}
            name="slack.enabled"
            render={({ field }) => (
              <ChannelToggle
                id="alerts-slack"
                label="Send alerts to Slack"
                checked={field.value}
                onCheckedChange={field.onChange}
              />
            )}
          />
          {slackOn &&
            (slackTargets.length ? (
              <Controller
                control={form.control}
                name="slack.channel_ids"
                render={({ field }) => (
                  <ul className="flex flex-col gap-2 pl-1">
                    {slackTargets.map((target) => {
                      const id = `alerts-slack-${target.channel_id}`;
                      return (
                        <li
                          key={target.channel_id}
                          className="flex items-center gap-2"
                        >
                          <Checkbox
                            id={id}
                            size="sm"
                            checked={field.value.includes(target.channel_id)}
                            onCheckedChange={(checked) =>
                              field.onChange(
                                toggleId(
                                  field.value,
                                  target.channel_id,
                                  checked === true,
                                ),
                              )
                            }
                          />
                          <label
                            htmlFor={id}
                            className="text-text-neutral-secondary text-sm"
                          >
                            #{target.name.replace(/^#/, "")}
                          </label>
                        </li>
                      );
                    })}
                  </ul>
                )}
              />
            ) : (
              <p className="text-text-neutral-tertiary text-sm">
                No confirmed Slack channel yet.{" "}
                <Button variant="link" size="link-sm" asChild>
                  <Link href={SLACK_INTEGRATIONS_PATH}>
                    Connect Slack in Integrations
                  </Link>
                </Button>
              </p>
            ))}
          {errors.slack?.message && (
            <FieldError>{errors.slack.message}</FieldError>
          )}
        </div>

        <div className="border-border-neutral-secondary flex flex-col gap-3 border-t pt-4">
          <Controller
            control={form.control}
            name="email.enabled"
            render={({ field }) => (
              <ChannelToggle
                id="alerts-email"
                label="Send alerts by email"
                checked={field.value}
                onCheckedChange={field.onChange}
              />
            )}
          />
          {emailOn &&
            (emailTargets.length ? (
              <Controller
                control={form.control}
                name="email.recipient_ids"
                render={({ field }) => (
                  <ul className="flex flex-col gap-2 pl-1">
                    {emailTargets.map((target) => {
                      const id = `alerts-email-${target.id}`;
                      const selectable = isSelectableRecipient(target);
                      return (
                        <li key={target.id} className="flex items-center gap-2">
                          <Checkbox
                            id={id}
                            size="sm"
                            disabled={!selectable}
                            checked={field.value.includes(target.id)}
                            onCheckedChange={(checked) =>
                              field.onChange(
                                toggleId(
                                  field.value,
                                  target.id,
                                  checked === true,
                                ),
                              )
                            }
                          />
                          <label
                            htmlFor={id}
                            className="text-text-neutral-secondary text-sm"
                          >
                            {target.email}
                          </label>
                          {!selectable && (
                            <Badge variant="tag">
                              {recipientStatusLabel(target.status)}
                            </Badge>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                )}
              />
            ) : (
              <p className="text-text-neutral-tertiary text-sm">
                No email recipient yet.{" "}
                <Button variant="link" size="link-sm" asChild>
                  <Link href={ALERTS_PATH}>Add one in Alerts</Link>
                </Button>
              </p>
            ))}
          {emailOn && emailTargets.length > 0 && (
            <span className="text-text-neutral-tertiary text-xs">
              Only recipients who confirmed their address can receive alerts.
            </span>
          )}
          {errors.email?.message && (
            <FieldError>{errors.email.message}</FieldError>
          )}
        </div>

        <Field className="max-w-xs">
          <FieldLabel htmlFor="alerts-severity">Minimum severity</FieldLabel>
          <Controller
            control={form.control}
            name="min_severity"
            render={({ field }) => (
              <Select value={field.value} onValueChange={field.onChange}>
                <SelectTrigger
                  id="alerts-severity"
                  size="sm"
                  disabled={!canManage}
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITY_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          />
        </Field>
        {errors.root?.server?.message && (
          <FieldError>{errors.root.server.message}</FieldError>
        )}
      </fieldset>
      <SectionFooter
        onCancel={onClose}
        submitLabel="Save alerts"
        pending={isSubmitting}
        disabled={!canManage}
      />
    </form>
  );
}
