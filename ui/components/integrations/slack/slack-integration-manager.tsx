"use client";

import { format, isValid, parseISO } from "date-fns";
import { Send, TestTube } from "lucide-react";
import { useEffect, useState } from "react";

import { testIntegrationConnection } from "@/actions/integrations/integrations";
import {
  getSlackChannels,
  sendSlackTestMessage,
  setSlackDefaultChannel,
} from "@/actions/integrations/slack";
import { SlackIcon } from "@/components/icons/services/IconServices";
import { IntegrationCardHeader } from "@/components/integrations/shared";
import { SlackChannelSelector } from "@/components/integrations/slack/slack-channel-selector";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Card,
  CardContent,
  CardHeader,
  useToast,
} from "@/components/shadcn";
import type {
  IntegrationProps,
  SlackChannelOption,
} from "@/types/integrations";

/** What the user was told about the last test message they sent. */
interface TestMessageOutcome {
  sent: boolean;
  detail: string;
}

interface SlackIntegrationManagerProps {
  /** At most one exists per tenant (one workspace). */
  integration: IntegrationProps | null;
  authorizeUrl: string | null;
  /** This deployment has no Prowler Slack app, so no install can be started. */
  unavailable: boolean;
  rateLimitMessage: string | null;
  loadError: string | null;
}

export const SlackIntegrationManager = ({
  integration,
  authorizeUrl,
  unavailable,
  rateLimitMessage,
  loadError,
}: SlackIntegrationManagerProps) => {
  const [isTesting, setIsTesting] = useState(false);
  const { toast } = useToast();

  const integrationId = integration?.id ?? null;
  const recordedChannelId =
    integration?.attributes.configuration.channel_id ?? null;
  const recordedChannelName =
    integration?.attributes.configuration.channel_name ?? null;

  const [channels, setChannels] = useState<SlackChannelOption[]>([]);
  const [channelsError, setChannelsError] = useState<string | null>(null);
  const [isLoadingChannels, setIsLoadingChannels] = useState(false);
  // Bumped by the refresh affordance: a channel invited to in Slack after the
  // page loaded only shows up on a re-read.
  const [channelReloads, setChannelReloads] = useState(0);
  // Local state needed: the pick is buffered until the user saves it.
  const [selectedChannelId, setSelectedChannelId] = useState<string | null>(
    recordedChannelId,
  );
  // What the API has on record. Mirrored in state rather than read from the
  // integration prop so that every affordance gated on a destination — the
  // connection check, the test message, the copy naming the channel — moves the
  // moment the save is acknowledged, instead of waiting on the revalidation
  // that refreshes this page's server component afterwards.
  const [defaultChannelId, setDefaultChannelId] = useState<string | null>(
    recordedChannelId,
  );
  const [defaultChannelName, setDefaultChannelName] = useState<string | null>(
    recordedChannelName,
  );
  // The prop the mirror was last taken from. A refresh of this page's data —
  // the revalidation above, or a change made in another tab — moves the record
  // under a card that never unmounts, and a mirror seeded only at mount would
  // go on naming a channel Prowler no longer posts to.
  const [syncedChannelId, setSyncedChannelId] = useState(recordedChannelId);
  const [syncedChannelName, setSyncedChannelName] =
    useState(recordedChannelName);
  const [isSavingChannel, setIsSavingChannel] = useState(false);
  const [isSendingTestMessage, setIsSendingTestMessage] = useState(false);
  const [testMessageOutcome, setTestMessageOutcome] =
    useState<TestMessageOutcome | null>(null);

  if (
    recordedChannelId !== syncedChannelId ||
    recordedChannelName !== syncedChannelName
  ) {
    setSyncedChannelId(recordedChannelId);
    setSyncedChannelName(recordedChannelName);
    setDefaultChannelId(recordedChannelId);
    setDefaultChannelName(recordedChannelName);
    // The buffered pick follows only while it still shows the destination that
    // was on record: a pick the user has made and not yet saved is theirs, and
    // overwriting it would take the choice away mid-edit.
    if (selectedChannelId === syncedChannelId) {
      setSelectedChannelId(recordedChannelId);
    }
  }

  useEffect(() => {
    if (!integrationId) return;

    let cancelled = false;
    setIsLoadingChannels(true);

    getSlackChannels(integrationId)
      .then((result) => {
        if (cancelled) return;

        if ("error" in result) {
          setChannels([]);
          setChannelsError(result.error);
        } else {
          setChannels(result.channels);
          setChannelsError(null);
        }
      })
      .catch(() => {
        if (cancelled) return;
        setChannels([]);
        setChannelsError("Could not reach Slack to read the channel list.");
      })
      .finally(() => {
        if (!cancelled) setIsLoadingChannels(false);
      });

    return () => {
      cancelled = true;
    };
  }, [integrationId, channelReloads]);

  const handleSaveChannel = async () => {
    if (!integrationId || !selectedChannelId) return;

    setIsSavingChannel(true);
    try {
      // Only the id travels: the API validates it against Slack and derives the
      // channel's name itself (design D6), so a name sent from here could only
      // ever drift from the id it belongs to.
      const result = await setSlackDefaultChannel(
        integrationId,
        selectedChannelId,
      );

      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Could not save the destination channel",
          description: result.error,
        });
        return;
      }

      // The name the API derived from the id, not the one this page happened to
      // have in its list: a channel renamed in Slack since the list was read
      // would otherwise be shown under its old name.
      const savedName =
        result.integration.attributes.configuration.channel_name ??
        channels.find((channel) => channel.id === selectedChannelId)?.name ??
        null;

      setDefaultChannelId(selectedChannelId);
      setDefaultChannelName(savedName);
      setTestMessageOutcome(null);
      toast({
        title: "Destination channel saved",
        description: savedName
          ? `Prowler will post to #${savedName}.`
          : "Prowler will post to the channel you chose.",
      });
    } catch (_error) {
      toast({
        variant: "destructive",
        title: "Could not save the destination channel",
        description: "Something went wrong. Please try again.",
      });
    } finally {
      setIsSavingChannel(false);
    }
  };

  const handleSendTestMessage = async () => {
    if (!integrationId) return;

    setIsSendingTestMessage(true);
    setTestMessageOutcome(null);
    try {
      const result = await sendSlackTestMessage(integrationId);

      setTestMessageOutcome(
        "sent" in result
          ? {
              sent: true,
              detail: defaultChannelName
                ? `Prowler posted a test message to #${defaultChannelName}.`
                : "Prowler posted a test message to your default channel.",
            }
          : { sent: false, detail: result.error },
      );
    } catch (_error) {
      setTestMessageOutcome({
        sent: false,
        detail: "Something went wrong. Please try again.",
      });
    } finally {
      setIsSendingTestMessage(false);
    }
  };

  const handleTestConnection = async (id: string) => {
    setIsTesting(true);
    try {
      const result = await testIntegrationConnection(id);

      if (result.success) {
        toast({
          title: "Connection test successful!",
          description:
            result.message || "Prowler can reach your Slack workspace.",
        });
      } else {
        toast({
          variant: "destructive",
          title: "Connection test failed",
          description: result.error || "Failed to reach your Slack workspace.",
        });
      }
    } catch (_error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to test connection. Please try again.",
      });
    } finally {
      setIsTesting(false);
    }
  };

  const workspaceName = integration?.attributes.configuration.team_name;

  const checkedAt = integration?.attributes.connection_last_checked_at;
  const checkedOn = checkedAt ? parseISO(checkedAt) : null;
  // `format` throws a RangeError on an unreadable value, which would replace
  // the page with the route's error boundary: show nothing instead, as for a
  // connection that was never checked.
  const lastCheckedOn =
    checkedOn && isValid(checkedOn) ? format(checkedOn, "yyyy/MM/dd") : null;

  return (
    <div className="flex flex-col gap-6">
      {rateLimitMessage && (
        <Alert variant="warning">
          <AlertTitle>Slack is busy right now</AlertTitle>
          <AlertDescription>{rateLimitMessage}</AlertDescription>
        </Alert>
      )}

      {loadError && (
        <Alert variant="error">
          <AlertTitle>Could not load your Slack integration</AlertTitle>
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      )}

      {/* Replaces the cards, not the whole page: an early return here would
          swallow the rate-limit and load-error notices above. */}
      {unavailable ? (
        <Alert variant="info">
          <AlertTitle>
            Slack is not available in this environment yet
          </AlertTitle>
          <AlertDescription>
            The Prowler Slack app is not configured here, so no workspace can be
            connected. Nothing to do on your side — this page starts working as
            soon as it is.
          </AlertDescription>
        </Alert>
      ) : integration ? (
        <Card variant="base">
          <CardHeader>
            <IntegrationCardHeader
              icon={<SlackIcon size={32} />}
              title={`Connected to ${workspaceName ?? "your Slack workspace"}`}
              subtitle="Prowler posts to this workspace only."
              connectionStatus={{
                connected: integration.attributes.connected,
              }}
            />
          </CardHeader>

          <CardContent className="pt-0">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-xs text-gray-500 dark:text-gray-300">
                {lastCheckedOn && (
                  <p>
                    <span className="font-medium">Last checked:</span>{" "}
                    {lastCheckedOn}
                  </p>
                )}
                {!defaultChannelId && (
                  <p>
                    Choosing a destination channel is the next step — the
                    connection is checked against it.
                  </p>
                )}
              </div>
              {/* The check posts to the destination channel: the API answers
                  400 when none is recorded yet. */}
              <Button
                size="sm"
                variant="outline"
                disabled={isTesting || !defaultChannelId}
                onClick={() => handleTestConnection(integration.id)}
              >
                <TestTube size={14} />
                {isTesting ? "Testing..." : "Test connection"}
              </Button>
            </div>

            <div className="border-border-neutral-secondary mt-6 flex flex-col gap-4 border-t pt-6">
              <SlackChannelSelector
                options={channels}
                value={selectedChannelId}
                onChange={setSelectedChannelId}
                isLoading={isLoadingChannels}
                error={channelsError}
                onRefresh={() => setChannelReloads((reloads) => reloads + 1)}
                disabled={isSavingChannel}
              />

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-text-neutral-secondary text-xs">
                  {defaultChannelName
                    ? `Prowler posts to #${defaultChannelName}.`
                    : "No destination channel recorded yet."}
                </p>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    disabled={
                      !selectedChannelId ||
                      selectedChannelId === defaultChannelId ||
                      isSavingChannel
                    }
                    onClick={handleSaveChannel}
                  >
                    {isSavingChannel ? "Saving..." : "Save channel"}
                  </Button>
                  {/* Nothing to prove delivery to until a channel is recorded. */}
                  {defaultChannelId && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={isSendingTestMessage}
                      onClick={handleSendTestMessage}
                    >
                      <Send size={14} />
                      {isSendingTestMessage
                        ? "Sending..."
                        : "Send test message"}
                    </Button>
                  )}
                </div>
              </div>

              {testMessageOutcome && (
                <Alert variant={testMessageOutcome.sent ? "success" : "error"}>
                  <AlertTitle>
                    {testMessageOutcome.sent
                      ? "Test message sent"
                      : "Test message failed"}
                  </AlertTitle>
                  <AlertDescription>
                    {testMessageOutcome.detail}
                  </AlertDescription>
                </Alert>
              )}
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card variant="base">
          <CardHeader>
            <IntegrationCardHeader
              icon={<SlackIcon size={32} />}
              title="No workspace connected"
              subtitle="Approve Prowler in Slack to connect a workspace. No tokens to copy."
            />
          </CardHeader>

          <CardContent className="pt-0">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <p className="text-sm text-gray-600 dark:text-gray-300">
                Prowler asks for permission to post messages and to read the
                workspace&apos;s channel list.
              </p>
              {authorizeUrl ? (
                <Button asChild>
                  <a href={authorizeUrl} rel="noopener noreferrer">
                    <SlackIcon size={16} />
                    Add to Slack
                  </a>
                </Button>
              ) : (
                <Button disabled>
                  <SlackIcon size={16} />
                  Add to Slack
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
