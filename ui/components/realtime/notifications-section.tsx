"use client";

import Link from "next/link";
import { useId, useState } from "react";

import {
  getRealtimeNotificationTargets,
  saveRealtimeNotifications,
} from "@/actions/realtime";
import { RealtimeSection } from "@/components/realtime/realtime-stat-card";
import {
  PanelFailure,
  PanelLoading,
} from "@/components/realtime/realtime-states";
import { ToggleRow } from "@/components/realtime/toggle-row";
import { useRealtimeResource } from "@/components/realtime/use-realtime-resource";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Checkbox } from "@/components/shadcn/checkbox";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { useToast } from "@/components/shadcn/toast";
import { humanize } from "@/lib/realtime/display";
import {
  ALERTS_PATH,
  isSelectableRecipient,
  recipientStatusLabel,
  SLACK_INTEGRATIONS_PATH,
  toggleId,
} from "@/lib/realtime/notifications";
import {
  DEFAULT_REALTIME_NOTIFICATIONS,
  realtimeNotificationsSchema,
} from "@/lib/realtime/policy-schema";
import {
  REALTIME_MIN_SEVERITY,
  type RealtimeNotifications,
  type RealtimeNotificationTargets,
  type RealtimePolicy,
} from "@/types/realtime";

interface AlertsSectionProps {
  providerId: string;
  policy: RealtimePolicy | null;
  canManage: boolean;
  onSaved: (policy: RealtimePolicy) => void;
}

const link = "text-button-tertiary underline underline-offset-4";

function ChoiceRow({
  id,
  checked,
  disabled,
  onChange,
  children,
  hint,
}: {
  id: string;
  checked: boolean;
  disabled: boolean;
  onChange: (checked: boolean) => void;
  children: string;
  hint?: string;
}) {
  return (
    <li className="flex items-center gap-2">
      <Checkbox
        id={id}
        size="sm"
        checked={checked}
        disabled={disabled}
        onCheckedChange={(value) => onChange(value === true)}
      />
      <label
        htmlFor={id}
        className={
          disabled && !checked
            ? "text-text-neutral-tertiary text-sm"
            : "text-text-neutral-primary text-sm"
        }
      >
        {children}
      </label>
      {hint && (
        <Badge variant="tag" size="sm">
          {hint}
        </Badge>
      )}
    </li>
  );
}

function SlackChannels({
  id,
  targets,
  selected,
  disabled,
  onChange,
}: {
  id: string;
  targets: RealtimeNotificationTargets;
  selected: string[];
  disabled: boolean;
  onChange: (ids: string[]) => void;
}) {
  const known = targets.slack.map((channel) => channel.channel_id);
  const gone = selected.filter((channel) => !known.includes(channel));
  return (
    <fieldset className="flex flex-col gap-2 pl-14">
      <legend className="text-text-neutral-secondary mb-1 text-xs font-medium">
        Slack channels
      </legend>
      {targets.slack.length === 0 && gone.length === 0 ? (
        <p className="text-text-neutral-tertiary text-sm">
          No Slack channel is available. Connect Slack in{" "}
          <Link href={SLACK_INTEGRATIONS_PATH} className={link}>
            Integrations
          </Link>{" "}
          first.
        </p>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {targets.slack.map((channel) => (
            <ChoiceRow
              key={channel.channel_id}
              id={`${id}-${channel.channel_id}`}
              checked={selected.includes(channel.channel_id)}
              disabled={disabled}
              onChange={(on) =>
                onChange(toggleId(selected, channel.channel_id, on))
              }
            >
              {`#${channel.name.replace(/^#/, "")}`}
            </ChoiceRow>
          ))}
          {gone.map((channel) => (
            <ChoiceRow
              key={channel}
              id={`${id}-${channel}`}
              checked
              disabled={disabled}
              hint="No longer available"
              onChange={(on) => onChange(toggleId(selected, channel, on))}
            >
              {channel}
            </ChoiceRow>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

function EmailRecipients({
  id,
  targets,
  selected,
  disabled,
  onChange,
}: {
  id: string;
  targets: RealtimeNotificationTargets;
  selected: string[];
  disabled: boolean;
  onChange: (ids: string[]) => void;
}) {
  const known = targets.email.map((recipient) => recipient.id);
  const gone = selected.filter((recipient) => !known.includes(recipient));
  return (
    <fieldset className="flex flex-col gap-2 pl-14">
      <legend className="text-text-neutral-secondary mb-1 text-xs font-medium">
        Email recipients
      </legend>
      {targets.email.length === 0 && gone.length === 0 ? (
        <p className="text-text-neutral-tertiary text-sm">
          No recipient exists yet. Add one in{" "}
          <Link href={ALERTS_PATH} className={link}>
            Alerts
          </Link>
          ; they must confirm by email before they can receive anything.
        </p>
      ) : (
        <ul className="flex flex-col gap-1.5">
          {targets.email.map((recipient) => {
            const selectable = isSelectableRecipient(recipient);
            return (
              <ChoiceRow
                key={recipient.id}
                id={`${id}-${recipient.id}`}
                checked={selected.includes(recipient.id)}
                // Only a confirmed recipient can be added; one that stopped
                // being confirmed can still be taken off.
                disabled={
                  disabled || (!selectable && !selected.includes(recipient.id))
                }
                hint={
                  selectable
                    ? undefined
                    : recipientStatusLabel(recipient.status)
                }
                onChange={(on) =>
                  onChange(toggleId(selected, recipient.id, on))
                }
              >
                {recipient.email}
              </ChoiceRow>
            );
          })}
          {gone.map((recipient) => (
            <ChoiceRow
              key={recipient}
              id={`${id}-${recipient}`}
              checked
              disabled={disabled}
              hint="No longer available"
              onChange={(on) => onChange(toggleId(selected, recipient, on))}
            >
              {recipient}
            </ChoiceRow>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

/** Where a validation message belongs: the Slack block, the email block or both. */
const fieldMessages = (notifications: RealtimeNotifications) => {
  const result = realtimeNotificationsSchema.safeParse(notifications);
  const messages: Record<string, string> = {};
  if (!result.success) {
    result.error.issues.forEach((issue) => {
      const field = String(issue.path[0] ?? "notifications");
      if (!messages[field]) messages[field] = issue.message;
    });
  }
  return messages;
};

/**
 * Alerts by Slack or email for what Prowler Realtime detects and does. Reused
 * by the setup wizard and the settings page; it saves only `notifications`.
 */
export function AlertsSection({
  providerId,
  policy,
  canManage,
  onSaved,
}: AlertsSectionProps) {
  const { toast } = useToast();
  const id = useId();
  const targets = useRealtimeResource(
    () => getRealtimeNotificationTargets(),
    "notification-targets",
  );
  const [draft, setDraft] = useState<RealtimeNotifications>(
    policy?.notifications ?? DEFAULT_REALTIME_NOTIFICATIONS,
  );
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  const disabled = !canManage || saving;
  const patch = (changes: Partial<RealtimeNotifications>) => {
    setDraft((current) => ({ ...current, ...changes }));
    setErrors({});
  };
  const anyOn = draft.slack.enabled || draft.email.enabled;

  const save = async () => {
    const found = fieldMessages(draft);
    if (Object.keys(found).length > 0) {
      setErrors(found);
      return;
    }
    setErrors({});
    setSaving(true);
    const result = await saveRealtimeNotifications({
      providerId,
      policyId: policy?.id,
      notifications: draft,
    });
    setSaving(false);
    if (result.ok) {
      onSaved(result.data);
      toast({ title: anyOn ? "Alerts saved" : "Alerts are off" });
    } else {
      // The API names unknown or unconfirmed destinations; show its words.
      setErrors({
        notifications:
          result.fieldErrors?.notifications ??
          Object.values(result.fieldErrors ?? {})[0] ??
          result.error,
      });
      toast({
        variant: "destructive",
        title:
          result.status === 403
            ? "You cannot change alerts"
            : "Could not save the alerts",
        description:
          result.status === 403
            ? "Changing alerts needs the Manage Realtime permission."
            : result.error,
      });
    }
  };

  return (
    <RealtimeSection
      title="Alerts"
      description="Get told in Slack or by email when Prowler Realtime detects a risky change and acts on it."
      action={
        <Badge variant={policy && anyOn ? "success" : "tag"}>
          {policy && anyOn ? "On" : "Off"}
        </Badge>
      }
    >
      <Alert variant="info">
        <AlertTitle>When an alert goes out</AlertTitle>
        <AlertDescription>
          <p>
            An alert is sent when a detection has a confirmed violation, with
            what Prowler did about it: fixed it, proposed a change, or only
            recorded it. Later, the result of a verified fix is sent too.
            Compliant, out-of-scope and failed checks never alert, and nothing
            below the minimum severity does. Nothing is sent until you turn a
            channel on.
          </p>
        </AlertDescription>
      </Alert>

      {targets.loading ? (
        <PanelLoading label="Loading alert destinations" />
      ) : targets.failure ? (
        <PanelFailure
          failure={targets.failure}
          onRetry={targets.reload}
          subject="the alert destinations"
        />
      ) : (
        <div className="flex flex-col gap-5">
          <ToggleRow
            id={`${id}-slack`}
            label="Send alerts to Slack"
            description="Post to the channels you pick, through your Slack integration."
            checked={draft.slack.enabled}
            disabled={disabled}
            onChange={(enabled) =>
              patch({ slack: { ...draft.slack, enabled } })
            }
          />
          {draft.slack.enabled && targets.data && (
            <SlackChannels
              id={`${id}-slack-channel`}
              targets={targets.data}
              selected={draft.slack.channel_ids}
              disabled={disabled}
              onChange={(channel_ids) =>
                patch({ slack: { ...draft.slack, channel_ids } })
              }
            />
          )}
          {errors.slack && <FieldError>{errors.slack}</FieldError>}

          <ToggleRow
            id={`${id}-email`}
            label="Send alerts by email"
            description="Email the confirmed recipients you pick."
            checked={draft.email.enabled}
            disabled={disabled}
            onChange={(enabled) =>
              patch({ email: { ...draft.email, enabled } })
            }
          />
          {draft.email.enabled && targets.data && (
            <EmailRecipients
              id={`${id}-email-recipient`}
              targets={targets.data}
              selected={draft.email.recipient_ids}
              disabled={disabled}
              onChange={(recipient_ids) =>
                patch({ email: { ...draft.email, recipient_ids } })
              }
            />
          )}
          {errors.email && <FieldError>{errors.email}</FieldError>}

          <Field className="max-w-xs">
            <FieldLabel htmlFor={`${id}-severity`}>
              Minimum severity to alert
            </FieldLabel>
            <Select
              value={draft.min_severity}
              disabled={disabled}
              onValueChange={(value) =>
                patch({
                  min_severity: value as RealtimeNotifications["min_severity"],
                })
              }
            >
              <SelectTrigger id={`${id}-severity`} size="sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.values(REALTIME_MIN_SEVERITY).map((severity) => (
                  <SelectItem key={severity} value={severity}>
                    {humanize(severity)} and above
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>

          <p className="text-text-neutral-tertiary text-xs">
            New destinations are created in{" "}
            <Link href={SLACK_INTEGRATIONS_PATH} className={link}>
              Integrations
            </Link>{" "}
            (Slack) and{" "}
            <Link href={ALERTS_PATH} className={link}>
              Alerts
            </Link>{" "}
            (email recipients, who must confirm by email first).
          </p>

          {errors.notifications && (
            <FieldError>{errors.notifications}</FieldError>
          )}

          {canManage ? (
            <div>
              <Button disabled={saving} onClick={() => void save()}>
                {saving ? "Saving…" : "Save alerts"}
              </Button>
            </div>
          ) : (
            <p className="text-text-neutral-tertiary text-sm">
              Read only: changing alerts needs the Manage Realtime permission.
            </p>
          )}
        </div>
      )}
    </RealtimeSection>
  );
}
