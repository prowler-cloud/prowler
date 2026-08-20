"use client";

import Link from "next/link";
import { useState } from "react";

import { getIntegrations } from "@/actions/integrations/integrations";
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
import type {
  IntegrationProps,
  SlackChannelOption,
} from "@/types/integrations";

const SLACK_INTEGRATION_HREF = "/integrations/slack";

const NO_INTEGRATION_COPY =
  "Posting alerts to Slack channels needs a connected Slack workspace.";
const NO_INTEGRATION_WITH_STORED_COPY =
  "Channel delivery is unavailable until a Slack workspace is connected.";
const EMPTY_POOL_COPY =
  "No channels are authorized yet. Authorize channels on the Slack integration to offer them here.";

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

interface SlackChannelsFieldProps {
  selectedChannelIds: string[];
  /**
   * The rule's stored channels from the read model (id, name, privacy), so a
   * channel missing from the authorized set — or the whole workspace being
   * gone — never blanks the stored selection.
   */
  storedChannels: SlackChannelOption[];
  onValuesChange: (channelIds: string[]) => void;
}

/**
 * The authorized set is the pool; the stored selection is merged in so a
 * de-authorized channel stays visible and selected until the user removes it.
 */
const mergeOptions = (
  authorized: SlackChannelOption[],
  stored: SlackChannelOption[],
): SlackChannelOption[] => {
  const byId = new Map(authorized.map((channel) => [channel.id, channel]));
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
    data-alert-channels-notice
    className="text-text-neutral-secondary flex flex-wrap items-center gap-1 text-xs"
  >
    <span>{copy}</span>
    <ManageIntegrationLink />
  </p>
);

/**
 * Slack channel destinations for an alert rule (design D4): reads the
 * tenant's Slack integration on mount — never the workspace listing (D2), so
 * there is no pagination and no listing-failure state — and offers exactly
 * the integration's authorized channels.
 */
export const SlackChannelsField = ({
  selectedChannelIds,
  storedChannels,
  onValuesChange,
}: SlackChannelsFieldProps) => {
  const [loading, setLoading] = useState(true);
  const [authorizedChannels, setAuthorizedChannels] = useState<
    SlackChannelOption[]
  >([]);
  const [connected, setConnected] = useState(false);

  useMountEffect(() => {
    getIntegrations(
      new URLSearchParams({ "filter[integration_type]": "slack" }),
    ).then((result) => {
      setLoading(false);
      // A failed read collapses to the disconnected presentation: the spec
      // allows exactly three states, and the integration page is where a
      // read problem gets diagnosed.
      if (result?.error) return;
      const integration = (result?.data as IntegrationProps[] | undefined)?.[0];
      if (!integration) return;
      setConnected(true);
      setAuthorizedChannels(
        integration.attributes.configuration.channels ?? [],
      );
    });
  });

  const options = mergeOptions(authorizedChannels, storedChannels);
  const state: FieldState = connected
    ? authorizedChannels.length > 0
      ? FIELD_STATE.POPULATED
      : FIELD_STATE.EMPTY_POOL
    : FIELD_STATE.NO_INTEGRATION;

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
        {storedChannels.length > 0 ? (
          // The stored selection stays visible and identified; only a
          // connected workspace makes it editable again.
          <SlackChannelMultiSelect
            options={options}
            values={selectedChannelIds}
            onChange={onValuesChange}
            disabled
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
                      disabled
                    >
                      <MultiSelectValue placeholder="Requires a connected Slack workspace" />
                    </MultiSelectTrigger>
                  </MultiSelect>
                </span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs">
                {NO_INTEGRATION_COPY}
              </TooltipContent>
            </Tooltip>
          </>
        )}
        <FieldNotice
          copy={
            storedChannels.length > 0
              ? NO_INTEGRATION_WITH_STORED_COPY
              : NO_INTEGRATION_COPY
          }
        />
      </div>
    );
  }

  if (state === FIELD_STATE.EMPTY_POOL && options.length === 0) {
    return (
      <div data-alert-channels-state={state} className="flex flex-col gap-2">
        <Label>Destination channels</Label>
        <FieldNotice copy={EMPTY_POOL_COPY} />
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
      {state === FIELD_STATE.EMPTY_POOL && (
        <FieldNotice copy={EMPTY_POOL_COPY} />
      )}
    </div>
  );
};
