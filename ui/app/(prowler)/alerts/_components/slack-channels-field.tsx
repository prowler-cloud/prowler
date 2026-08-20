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
import type {
  IntegrationProps,
  SlackChannelOption,
} from "@/types/integrations";

const SLACK_INTEGRATION_HREF = "/integrations/slack";

const NO_INTEGRATION_COPY =
  "Posting alerts to Slack channels needs a connected Slack workspace.";
const EMPTY_POOL_COPY =
  "No channels are ready yet. Authorize channels on the Slack integration and run its connection check to offer them here.";

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

/** `GET /alerts/slack-channels` — id is the channel id (contract section 2). */
interface EligibleChannelResource {
  id: string;
  attributes: { name: string; is_private: boolean };
}

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

const toChannelOptions = (data: unknown): SlackChannelOption[] =>
  Array.isArray(data)
    ? (data as EligibleChannelResource[]).map((resource) => ({
        id: resource.id,
        name: resource.attributes.name,
        is_private: resource.attributes.is_private,
      }))
    : [];

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
    data-alert-channels-notice
    className="text-text-neutral-secondary flex flex-wrap items-center gap-1 text-xs"
  >
    <span>{copy}</span>
    <ManageIntegrationLink />
  </p>
);

/**
 * Slack channel destinations for an alert rule (design D2/D4): the options
 * come from the dedicated eligible-channels endpoint — never the workspace
 * listing, so there is no pagination and no listing-failure state — and the
 * integration is read only to tell an empty pool from no workspace at all,
 * which an empty collection cannot say on its own.
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
  const [integrationUsable, setIntegrationUsable] = useState(false);

  useMountEffect(() => {
    Promise.all([
      getAlertSlackChannels(),
      getIntegrations(
        new URLSearchParams({ "filter[integration_type]": "slack" }),
      ),
    ]).then(([channelsResult, integrationsResult]) => {
      setLoading(false);
      // A failed read collapses to the disabled presentation: the spec allows
      // exactly three states, and the integration page is where a read
      // problem gets diagnosed.
      if (!channelsResult?.error) {
        setEligibleChannels(toChannelOptions(channelsResult?.data));
      }
      if (integrationsResult?.error) return;
      const integration = (
        integrationsResult?.data as IntegrationProps[] | undefined
      )?.[0];
      setIntegrationUsable(
        Boolean(integration?.attributes.enabled) &&
          integration?.attributes.connected === true,
      );
    });
  });

  const options = mergeOptions(eligibleChannels, storedChannels);
  // Eligibility decides the state; the merged stored channels only decide what
  // an already-saved rule renders.
  const state: FieldState =
    eligibleChannels.length > 0
      ? FIELD_STATE.POPULATED
      : integrationUsable
        ? FIELD_STATE.EMPTY_POOL
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
        {options.length > 0 ? (
          // A rule keeps its channels while its workspace is unverified — a
          // reinstall resets the confirmations, not the mappings — so the
          // stored selection stays readable until the check runs again.
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
        <FieldNotice copy={NO_INTEGRATION_COPY} />
      </div>
    );
  }

  if (state === FIELD_STATE.EMPTY_POOL) {
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
    </div>
  );
};
