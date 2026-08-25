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

// Only one notice renders per state, so a shared id stays unique.
const CHANNELS_NOTICE_ID = "alert-slack-channels-notice";

const NO_INTEGRATION_COPY =
  "Posting alerts to Slack channels needs a connected Slack workspace.";
const UNVERIFIED_COPY =
  "The Slack workspace has not passed a connection check yet. Run it on the Slack integration to offer its channels here.";
const EMPTY_POOL_COPY =
  "No channels are ready yet. Authorize channels on the Slack integration and run its connection check to offer them here.";
const UNKNOWN_COPY =
  "The Slack workspace status could not be checked. Its channels may still be available on the Slack integration.";

// Read by the page harness off `data-alert-channels-state`.
const FIELD_STATE = {
  NO_INTEGRATION: "no-integration",
  EMPTY_POOL: "empty-pool",
  POPULATED: "populated",
} as const;

type FieldState = (typeof FIELD_STATE)[keyof typeof FIELD_STATE];

/**
 * Read only by the notice copy, never by the presentation: a failed read must
 * not be told as a missing workspace. `/integrations` gates even reads behind
 * `MANAGE_INTEGRATIONS`, so non-admins get a 403 there while
 * `/alerts/slack-channels` answers them.
 */
const WORKSPACE = {
  READY: "ready",
  /** Present, but disabled or not confirmed by a check. */
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
  /** Merged into the options while selected, so stored channels still render. */
  storedChannels: SlackChannelOption[];
  onValuesChange: (channelIds: string[]) => void;
}

// Skips malformed resources: one bad element would otherwise empty the picker.
const toChannelOptions = (data: unknown): SlackChannelOption[] => {
  if (!Array.isArray(data)) return [];

  const channels: SlackChannelOption[] = [];
  for (const resource of data) {
    const channelId = resource?.id;
    if (typeof channelId !== "string" || channelId.length === 0) continue;
    const name = resource?.attributes?.name;
    channels.push({
      id: channelId,
      // The shared picker sorts `name` with `localeCompare`; non-strings throw.
      name: typeof name === "string" ? name : "",
      is_private: Boolean(resource?.attributes?.is_private),
    });
  }
  return channels;
};

const mergeOptions = (
  eligible: SlackChannelOption[],
  stored: SlackChannelOption[],
  selectedIds: string[],
): SlackChannelOption[] => {
  const byId = new Map(eligible.map((channel) => [channel.id, channel]));
  // A stored channel outside the pool is kept only while it stays selected:
  // deselecting it must not leave it offered for a pick the write refuses.
  stored.forEach((channel) => {
    if (!byId.has(channel.id) && selectedIds.includes(channel.id)) {
      byId.set(channel.id, channel);
    }
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

// Only rendered alongside a notice, so `describedBy` always has a target.
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
 * The integration is read only to tell an empty pool from no workspace at
 * all, which an empty channel collection cannot say on its own.
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
        // A failed read leaves the workspace unknown, not "no Slack at all".
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
      // A >= 500 answer throws past the action's own catch; without this the
      // field never leaves its loading skeleton.
      .catch(() => undefined)
      .finally(() => setLoading(false));
  });

  const options = mergeOptions(
    eligibleChannels,
    storedChannels,
    selectedChannelIds,
  );
  // Eligibility decides the state, not the merged stored channels.
  const state: FieldState =
    eligibleChannels.length > 0
      ? FIELD_STATE.POPULATED
      : workspace === WORKSPACE.READY
        ? FIELD_STATE.EMPTY_POOL
        : FIELD_STATE.NO_INTEGRATION;

  // An unreadable pool says nothing about the workspace either.
  const noticeCopy = channelsReadable
    ? WORKSPACE_COPY[workspace]
    : UNKNOWN_COPY;

  // No `data-alert-channels-state` here: its absence is what makes the page
  // harness wait for a settled state instead of latching this one.
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
          // Retained ids never refuse a save: only channels just added are
          // validated (contract 6.3).
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
                      // The reason must travel with the control; the tooltip
                      // only reaches a pointer or the wrapper's focus.
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
