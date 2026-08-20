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

const CHANNELS_STATUS = {
  LOADING: "loading",
  ERROR: "error",
  LOADED: "loaded",
} as const;

interface ChannelsLoading {
  status: typeof CHANNELS_STATUS.LOADING;
}

interface ChannelsFailed {
  status: typeof CHANNELS_STATUS.ERROR;
  message: string;
}

interface ChannelsLoaded {
  status: typeof CHANNELS_STATUS.LOADED;
  channels: SlackChannelOption[];
  // Rides with the list it qualifies, so it can never outlive it.
  notice: string | null;
}

type ChannelsState = ChannelsLoading | ChannelsFailed | ChannelsLoaded;

const TEST_MESSAGE_STATUS = {
  IDLE: "idle",
  SENDING: "sending",
  SENT: "sent",
  FAILED: "failed",
} as const;

interface TestMessageIdle {
  status: typeof TEST_MESSAGE_STATUS.IDLE;
}

interface TestMessageSending {
  status: typeof TEST_MESSAGE_STATUS.SENDING;
}

interface TestMessageSent {
  status: typeof TEST_MESSAGE_STATUS.SENT;
  detail: string;
}

interface TestMessageFailed {
  status: typeof TEST_MESSAGE_STATUS.FAILED;
  detail: string;
}

type TestMessageState =
  | TestMessageIdle
  | TestMessageSending
  | TestMessageSent
  | TestMessageFailed;

/** Ties the disabled check to the copy saying what unblocks it. */
const CHECK_BLOCKED_REASON_ID = "slack-connection-check-blocked";

// The name may be missing: the id decides what the UI can do with it.
interface SlackChannelRef {
  id: string;
  name: string | null;
}

const channelRefEquals = (
  a: SlackChannelRef | null,
  b: SlackChannelRef | null,
) => a?.id === b?.id && a?.name === b?.name;

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

  const recordedChannel: SlackChannelRef | null = recordedChannelId
    ? { id: recordedChannelId, name: recordedChannelName }
    : null;

  // Seeded `loading`, not by the effect: the effect never runs on the server,
  // so anything else would server-render a "no channels" picker until
  // hydration.
  const [channelsState, setChannelsState] = useState<ChannelsState>(
    integrationId
      ? { status: CHANNELS_STATUS.LOADING }
      : { status: CHANNELS_STATUS.LOADED, channels: [], notice: null },
  );
  // Bumped by refresh: a channel invited after load only shows on a re-read.
  const [channelReloads, setChannelReloads] = useState(0);
  // Local state needed: the pick is buffered until the user saves it.
  const [selectedChannelId, setSelectedChannelId] = useState<string | null>(
    recordedChannelId,
  );
  // Mirrored in state, not read from the prop, so channel-gated affordances
  // move on save instead of waiting for the revalidation.
  const [defaultChannel, setDefaultChannel] = useState(recordedChannel);
  // The prop the mirror was last taken from: the card never unmounts, so a
  // mirror seeded only at mount would go stale when the record changes.
  const [syncedChannel, setSyncedChannel] = useState(recordedChannel);
  const [isSavingChannel, setIsSavingChannel] = useState(false);
  const [testMessageState, setTestMessageState] = useState<TestMessageState>({
    status: TEST_MESSAGE_STATUS.IDLE,
  });

  if (!channelRefEquals(recordedChannel, syncedChannel)) {
    const previousSyncedId = syncedChannel?.id ?? null;
    setSyncedChannel(recordedChannel);
    setDefaultChannel(recordedChannel);
    // Follow the record only while the buffered pick still matches it: an
    // unsaved pick is the user's, not ours to overwrite mid-edit.
    if (selectedChannelId === previousSyncedId) {
      setSelectedChannelId(recordedChannel?.id ?? null);
    }
  }

  useEffect(() => {
    if (!integrationId) return;

    let cancelled = false;
    setChannelsState({ status: CHANNELS_STATUS.LOADING });

    getSlackChannels(integrationId)
      .then((result) => {
        if (cancelled) return;
        setChannelsState(
          "error" in result
            ? { status: CHANNELS_STATUS.ERROR, message: result.error }
            : {
                status: CHANNELS_STATUS.LOADED,
                channels: result.channels,
                notice: result.incomplete ?? null,
              },
        );
      })
      .catch(() => {
        if (cancelled) return;
        setChannelsState({
          status: CHANNELS_STATUS.ERROR,
          message: "Could not reach Slack to read the channel list.",
        });
      });

    return () => {
      cancelled = true;
    };
  }, [integrationId, channelReloads]);

  const channels =
    channelsState.status === CHANNELS_STATUS.LOADED
      ? channelsState.channels
      : [];

  const handleSaveChannel = async () => {
    if (!integrationId || !selectedChannelId) return;

    setIsSavingChannel(true);
    try {
      // Only the id travels — the API validates it and derives the name
      // (design D6).
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

      // Prefer the API's derived name: a channel renamed in Slack since the
      // list was read would otherwise show its old name.
      const savedName =
        result.integration.attributes.configuration.channel_name ??
        channels.find((channel) => channel.id === selectedChannelId)?.name ??
        null;

      setDefaultChannel({ id: selectedChannelId, name: savedName });
      // An outcome about the previous destination would mislead here.
      setTestMessageState({ status: TEST_MESSAGE_STATUS.IDLE });
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

    setTestMessageState({ status: TEST_MESSAGE_STATUS.SENDING });
    try {
      const result = await sendSlackTestMessage(integrationId);

      setTestMessageState(
        "sent" in result
          ? {
              status: TEST_MESSAGE_STATUS.SENT,
              detail: defaultChannel?.name
                ? `Prowler posted a test message to #${defaultChannel.name}.`
                : "Prowler posted a test message to your default channel.",
            }
          : { status: TEST_MESSAGE_STATUS.FAILED, detail: result.error },
      );
    } catch (_error) {
      setTestMessageState({
        status: TEST_MESSAGE_STATUS.FAILED,
        detail: "Something went wrong. Please try again.",
      });
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
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="text-xs text-gray-500 dark:text-gray-300">
                {lastCheckedOn && (
                  <p>
                    <span className="font-medium">Last checked:</span>{" "}
                    {lastCheckedOn}
                  </p>
                )}
              </div>
              <div className="flex flex-col items-start gap-1 sm:items-end">
                {/* The check posts to the destination channel: the API answers
                    400 when none is recorded yet. */}
                <Button
                  size="sm"
                  variant="outline"
                  disabled={isTesting || !defaultChannel}
                  // The reason travels with the control, not just somewhere on
                  // the page: a disabled button whose explanation sits across
                  // the row reads as broken.
                  aria-describedby={
                    defaultChannel ? undefined : CHECK_BLOCKED_REASON_ID
                  }
                  onClick={() => handleTestConnection(integration.id)}
                >
                  <TestTube size={14} />
                  {isTesting ? "Testing..." : "Test connection"}
                </Button>
                {!defaultChannel && (
                  <p
                    id={CHECK_BLOCKED_REASON_ID}
                    className="text-xs text-gray-500 dark:text-gray-300"
                  >
                    Choose a destination channel below to enable this check.
                  </p>
                )}
              </div>
            </div>

            <div className="border-border-neutral-secondary mt-6 flex flex-col gap-4 border-t pt-6">
              <SlackChannelSelector
                options={channels}
                value={selectedChannelId}
                onChange={setSelectedChannelId}
                isLoading={channelsState.status === CHANNELS_STATUS.LOADING}
                error={
                  channelsState.status === CHANNELS_STATUS.ERROR
                    ? channelsState.message
                    : null
                }
                incompleteNotice={
                  channelsState.status === CHANNELS_STATUS.LOADED
                    ? channelsState.notice
                    : null
                }
                onRefresh={() => setChannelReloads((reloads) => reloads + 1)}
                disabled={isSavingChannel}
              />

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-text-neutral-secondary text-xs">
                  {/* The id decides, not the name: a missing name would deny
                      a destination the test button posts to. */}
                  {defaultChannel
                    ? defaultChannel.name
                      ? `Prowler posts to #${defaultChannel.name}.`
                      : "Prowler posts to the channel you saved."
                    : "No destination channel recorded yet."}
                </p>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    disabled={
                      !selectedChannelId ||
                      selectedChannelId === (defaultChannel?.id ?? null) ||
                      isSavingChannel
                    }
                    onClick={handleSaveChannel}
                  >
                    {isSavingChannel ? "Saving..." : "Save channel"}
                  </Button>
                  {defaultChannel && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={
                        testMessageState.status === TEST_MESSAGE_STATUS.SENDING
                      }
                      onClick={handleSendTestMessage}
                    >
                      <Send size={14} />
                      {testMessageState.status === TEST_MESSAGE_STATUS.SENDING
                        ? "Sending..."
                        : "Send test message"}
                    </Button>
                  )}
                </div>
              </div>

              {(testMessageState.status === TEST_MESSAGE_STATUS.SENT ||
                testMessageState.status === TEST_MESSAGE_STATUS.FAILED) && (
                <Alert
                  variant={
                    testMessageState.status === TEST_MESSAGE_STATUS.SENT
                      ? "success"
                      : "error"
                  }
                >
                  <AlertTitle>
                    {testMessageState.status === TEST_MESSAGE_STATUS.SENT
                      ? "Test message sent"
                      : "Test message failed"}
                  </AlertTitle>
                  <AlertDescription>{testMessageState.detail}</AlertDescription>
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
