"use client";

import Link from "next/link";
import { useState } from "react";

import { getIntegrations } from "@/actions/integrations/integrations";
import { getAlertSlackChannels } from "@/app/(prowler)/alerts/_actions/slack-channels";
import { SlackChannelMultiSelect } from "@/components/integrations/slack/slack-channel-multi-select";
import {
  Button,
  Label,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import {
  MultiSelect,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import { useMountEffect } from "@/hooks/use-mount-effect";
import {
  INTEGRATION_TYPE,
  type IntegrationProps,
  type SlackChannelOption,
} from "@/types/integrations";

const SLACK_INTEGRATION_HREF = "/integrations/slack";

/**
 * The notice is what explains a disabled picker, so the picker points at it
 * rather than leaving the reason to adjacency. Only one notice renders per
 * state, so the id stays unique.
 */
const CHANNELS_NOTICE_ID = "alert-slack-channels-notice";

const NO_INTEGRATION_COPY =
  "Posting alerts to Slack channels needs a connected Slack workspace.";
const UNVERIFIED_COPY =
  "The Slack workspace has not passed a connection check yet. Run it on the Slack integration to offer its channels here.";
const EMPTY_POOL_COPY =
  "No channels are ready yet. Authorize channels on the Slack integration and run its connection check to offer them here.";
const UNKNOWN_COPY =
  "The Slack workspace status could not be checked. Its channels may still be available on the Slack integration.";

/**
 * The three presentations the spec allows (design D2/D4). Read by the page
 * harness off `data-alert-channels-state`.
 */
const FIELD_STATE = {
  NO_INTEGRATION: "no-integration",
  EMPTY_POOL: "empty-pool",
  POPULATED: "populated",
} as const;

type FieldState = (typeof FIELD_STATE)[keyof typeof FIELD_STATE];

/**
 * What the mount reads could establish about the workspace. Only the copy
 * reads it, never the presentation: a read that failed must not be told as a
 * workspace that is missing. `/integrations` gates even reads behind
 * `MANAGE_INTEGRATIONS`, so every non-admin gets a 403 there while
 * `/alerts/slack-channels` answers them normally.
 */
const WORKSPACE = {
  READY: "ready",
  /** A workspace is there; it is disabled, or no check has confirmed it. */
  UNVERIFIED: "unverified",
  MISSING: "missing",
  UNKNOWN: "unknown",
} as const;

type Workspace = (typeof WORKSPACE)[keyof typeof WORKSPACE];

/** A ready workspace only ever explains itself when its pool came back empty. */
const WORKSPACE_COPY: Record<Workspace, string> = {
  [WORKSPACE.READY]: EMPTY_POOL_COPY,
  [WORKSPACE.UNVERIFIED]: UNVERIFIED_COPY,
  [WORKSPACE.MISSING]: NO_INTEGRATION_COPY,
  [WORKSPACE.UNKNOWN]: UNKNOWN_COPY,
};

interface SlackChannelsFieldProps {
  selectedChannelIds: string[];
  /**
   * The rule's stored channels from the read model (id, name, privacy). They
   * are merged into the options so a channel that is configured but not yet
   * confirmed — what a same-workspace reinstall leaves behind — still renders
   * by name and privacy instead of blanking the stored selection.
   */
  storedChannels: SlackChannelOption[];
  onValuesChange: (channelIds: string[]) => void;
}

/**
 * `GET /alerts/slack-channels` — id is the channel id (contract section 2).
 * Mapped per resource, as the workspace listing is: one malformed element
 * would otherwise empty the whole picker.
 */
const toChannelOptions = (data: unknown): SlackChannelOption[] => {
  if (!Array.isArray(data)) return [];

  const channels: SlackChannelOption[] = [];
  for (const resource of data) {
    const channelId = resource?.id;
    if (typeof channelId !== "string" || channelId.length === 0) continue;
    const name = resource?.attributes?.name;
    channels.push({
      id: channelId,
      // The picker sorts on `name` through `localeCompare`, which anything
      // but a string takes the whole list down with.
      name: typeof name === "string" ? name : "",
      is_private: Boolean(resource?.attributes?.is_private),
    });
  }
  return channels;
};

const mergeOptions = (
  eligible: SlackChannelOption[],
  stored: SlackChannelOption[],
): SlackChannelOption[] => {
  const byId = new Map(eligible.map((channel) => [channel.id, channel]));
  stored.forEach((channel) => {
    if (!byId.has(channel.id)) byId.set(channel.id, channel);
  });
  return Array.from(byId.values());
};

const ManageIntegrationLink = () => (
  <Button variant="link" size="link-sm" className="h-auto p-0" asChild>
    <Link href={SLACK_INTEGRATION_HREF}>Manage the Slack integration</Link>
  </Button>
);

const FieldNotice = ({ copy }: { copy: string }) => (
  <p
    id={CHANNELS_NOTICE_ID}
    data-alert-channels-notice
    className="text-text-neutral-secondary flex flex-wrap items-center gap-1 text-xs"
  >
    <span>{copy}</span>
    <ManageIntegrationLink />
  </p>
);

interface StoredChannelsPickerProps {
  options: SlackChannelOption[];
  values: string[];
  onChange: (channelIds: string[]) => void;
}

/**
 * The rule's own channels, readable but not editable against a pool it left.
 * Only rendered alongside a notice, so it always has a reason to point at.
 */
const StoredChannelsPicker = ({
  options,
  values,
  onChange,
}: StoredChannelsPickerProps) => (
  <SlackChannelMultiSelect
    options={options}
    values={values}
    onChange={onChange}
    describedBy={CHANNELS_NOTICE_ID}
    disabled
  />
);

/**
 * Slack channel destinations for an alert rule (design D2/D4): the options
 * come from the dedicated eligible-channels endpoint rather than the Slack
 * workspace listing, so the field makes no Slack round-trip and carries none
 * of the cursor paging that listing needs. The integration is read only to
 * tell an empty pool from no workspace at all, which an empty collection
 * cannot say on its own — and, when a read fails, neither can the field.
 */
export const SlackChannelsField = ({
  selectedChannelIds,
  storedChannels,
  onValuesChange,
}: SlackChannelsFieldProps) => {
  const [loading, setLoading] = useState(true);
  const [eligibleChannels, setEligibleChannels] = useState<
    SlackChannelOption[]
  >([]);
  const [channelsReadable, setChannelsReadable] = useState(false);
  const [workspace, setWorkspace] = useState<Workspace>(WORKSPACE.UNKNOWN);

  useMountEffect(() => {
    Promise.all([
      getAlertSlackChannels(),
      getIntegrations(
        new URLSearchParams({
          "filter[integration_type]": INTEGRATION_TYPE.SLACK,
        }),
      ),
    ])
      .then(([channelsResult, integrationsResult]) => {
        if (!channelsResult?.error) {
          setChannelsReadable(true);
          setEligibleChannels(toChannelOptions(channelsResult?.data));
        }
        // A read that failed leaves the workspace unknown, so nothing below
        // claims the tenant has no Slack at all.
        if (integrationsResult?.error) return;

        const integration = (
          integrationsResult?.data as IntegrationProps[] | undefined
        )?.[0];
        if (!integration) {
          setWorkspace(WORKSPACE.MISSING);
          return;
        }
        setWorkspace(
          integration.attributes.enabled &&
            integration.attributes.connected === true
            ? WORKSPACE.READY
            : WORKSPACE.UNVERIFIED,
        );
      })
      // `handleApiResponse` throws on a 5xx and both actions return it
      // unawaited, so the rejection lands here. Sentry already captured it;
      // what matters is that the field leaves its loading skeleton.
      .catch(() => undefined)
      .finally(() => setLoading(false));
  });

  const options = mergeOptions(eligibleChannels, storedChannels);
  // Eligibility decides the state; the merged stored channels only decide what
  // an already-saved rule renders.
  const state: FieldState =
    eligibleChannels.length > 0
      ? FIELD_STATE.POPULATED
      : workspace === WORKSPACE.READY
        ? FIELD_STATE.EMPTY_POOL
        : FIELD_STATE.NO_INTEGRATION;

  // A pool that could not be read tells nothing about the workspace either,
  // so it drops back to the copy that claims nothing.
  const noticeCopy = channelsReadable
    ? WORKSPACE_COPY[workspace]
    : UNKNOWN_COPY;

  if (loading) {
    return (
      <div className="flex flex-col gap-2">
        <SlackChannelMultiSelect
          options={options}
          values={selectedChannelIds}
          onChange={onValuesChange}
          isLoading
          disabled
        />
      </div>
    );
  }

  if (state === FIELD_STATE.NO_INTEGRATION) {
    return (
      <div data-alert-channels-state={state} className="flex flex-col gap-2">
        {options.length > 0 ? (
          // A rule keeps its channels while its workspace is unverified — a
          // reinstall resets the confirmations, not the mappings — so the
          // stored selection stays readable, and retained ids never refuse a
          // save: only channels just added are validated (contract 6.3).
          <StoredChannelsPicker
            options={options}
            values={selectedChannelIds}
            onChange={onValuesChange}
          />
        ) : (
          <>
            <Label>Destination channels</Label>
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="inline-flex w-full" tabIndex={0}>
                  <MultiSelect values={[]} onValuesChange={() => undefined}>
                    <MultiSelectTrigger
                      id="slack-channels"
                      aria-label="Destination channels"
                      // Why it cannot be used travels with the control: the
                      // tooltip only reaches a pointer or the wrapper's focus.
                      aria-describedby={CHANNELS_NOTICE_ID}
                      disabled
                    >
                      <MultiSelectValue placeholder="No channels available" />
                    </MultiSelectTrigger>
                  </MultiSelect>
                </span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs">
                {noticeCopy}
              </TooltipContent>
            </Tooltip>
          </>
        )}
        <FieldNotice copy={noticeCopy} />
      </div>
    );
  }

  if (state === FIELD_STATE.EMPTY_POOL) {
    return (
      <div data-alert-channels-state={state} className="flex flex-col gap-2">
        {options.length > 0 ? (
          // The read model enriches from what is configured, the pool offers
          // only what is confirmed, so a rule can hold channels an empty pool
          // does not offer. Rendering the notice alone would hide them.
          <StoredChannelsPicker
            options={options}
            values={selectedChannelIds}
            onChange={onValuesChange}
          />
        ) : (
          <Label>Destination channels</Label>
        )}
        <FieldNotice copy={noticeCopy} />
      </div>
    );
  }

  return (
    <div data-alert-channels-state={state} className="flex flex-col gap-2">
      <SlackChannelMultiSelect
        options={options}
        values={selectedChannelIds}
        onChange={onValuesChange}
      />
    </div>
  );
};
