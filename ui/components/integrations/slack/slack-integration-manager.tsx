"use client";

import { format, isValid, parseISO } from "date-fns";
import { TestTube, Unplug } from "lucide-react";
import { useEffect, useState } from "react";

import { testIntegrationConnection } from "@/actions/integrations/integrations";
import {
  disconnectSlackIntegration,
  getSlackAuthorizeUrl,
  getSlackChannels,
  setSlackAuthorizedChannels,
} from "@/actions/integrations/slack";
import { SlackIcon } from "@/components/icons/services/IconServices";
import { IntegrationCardHeader } from "@/components/integrations/shared";
import { SlackChannelMultiSelect } from "@/components/integrations/slack/slack-channel-multi-select";
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
import { Modal } from "@/components/shadcn/modal";
import {
  isSlackTokenErrorCode,
  SLACK_REASON_TOKEN,
  slackErrorMessage,
} from "@/lib/integrations/slack-errors";
import type { SlackTokenErrorCode } from "@/lib/integrations/slack-errors";
import type {
  IntegrationProps,
  SlackAuthorizedChannel,
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

const CHECK_HINT_ID = "slack-connection-check-hint";

/**
 * What the connection check posts, word for word (contract, Connection). Named
 * here because the copy promises it: a user about to run the check sees exactly
 * what will land in their channels.
 */
const CONFIRMATION_MESSAGE =
  "✅ Prowler connection verified. Notifications will be delivered to this channel.";

/**
 * A disconnect that removed the row without Slack confirming the revocation.
 * The workspace name travels with it: the notice exists to name the workspace
 * to clean up, and the record is gone by the time revalidation lands.
 */
interface UnconfirmedRevocation {
  workspace: string | null;
}

/** Order-insensitive: the mirror must not re-seed on a mere reordering. */
const sameChannelIds = (a: string[], b: string[]) =>
  a.length === b.length && new Set([...a, ...b]).size === a.length;

/**
 * Confirmation counts as part of the record: a check that confirms a channel
 * changes nothing else, and the mirror has to follow it or the card would keep
 * offering to confirm what is already confirmed.
 */
const sameChannelSets = (
  a: SlackAuthorizedChannel[],
  b: SlackAuthorizedChannel[],
) => {
  if (a.length !== b.length) return false;
  const byId = new Map(a.map((channel) => [channel.id, channel]));
  return b.every((channel) => {
    const other = byId.get(channel.id);
    return (
      other?.name === channel.name &&
      other?.confirmation_sent_at === channel.confirmation_sent_at
    );
  });
};

/**
 * The listing's copy of a channel wins over the stored one (a rename in Slack
 * shows up there first), and a stored channel the listing no longer carries
 * stays offered: dropping it silently would deselect it behind the user's back.
 */
const mergeChannelOptions = (
  listed: SlackChannelOption[],
  stored: SlackAuthorizedChannel[],
): SlackChannelOption[] => {
  const merged = new Map(listed.map((channel) => [channel.id, channel]));
  stored.forEach(({ id, name, is_private }) => {
    // Narrowed on the way in: the picker offers channels, and whether Prowler
    // has confirmed one is no part of choosing it.
    if (!merged.has(id)) merged.set(id, { id, name, is_private });
  });
  return Array.from(merged.values());
};

/**
 * What the save recorded, for an answer that carried no channels back. Retained
 * ids keep the confirmation they had and new ones start without one, which is
 * the rule the API applies.
 */
const recordedFromSelection = (
  channelIds: string[],
  options: SlackChannelOption[],
  previous: SlackAuthorizedChannel[],
): SlackAuthorizedChannel[] =>
  channelIds.flatMap((channelId) => {
    const option = options.find((channel) => channel.id === channelId);
    if (!option) return [];
    const stored = previous.find((channel) => channel.id === channelId);
    return [
      { ...option, confirmation_sent_at: stored?.confirmation_sent_at ?? null },
    ];
  });

const channelList = (names: string[]): string =>
  new Intl.ListFormat("en", { style: "long", type: "conjunction" }).format(
    names.map((name) => `#${name}`),
  );

/**
 * Slack's own reason, when the string is one: the connection check reports a
 * reason and its own prose in the same field, and only a reason is an answer
 * from Slack about the credential.
 */
const asReasonCode = (reason: string | null): string | null =>
  reason && SLACK_REASON_TOKEN.test(reason) ? reason : null;

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
  const [isDisconnectOpen, setIsDisconnectOpen] = useState(false);
  const [isDisconnecting, setIsDisconnecting] = useState(false);
  // The row is gone the moment the API says so; the server component's
  // revalidation only catches up on the next navigation.
  const [disconnected, setDisconnected] = useState(false);
  const [unconfirmedRevocation, setUnconfirmedRevocation] =
    useState<UnconfirmedRevocation | null>(null);
  /**
   * The `code` of the last refusal any Slack-backed call ran into, or `null`
   * when the last answer was not a refusal. A dead grant can surface from any
   * of them (contract, Cross-cutting), so every call reports here instead of
   * deciding on its own.
   */
  const [lastRefusalCode, setLastRefusalCode] = useState<string | null>(null);
  // A connected workspace arrives with no consent URL, since no install is left
  // to start (design D10), so one is minted only if a reconnect turns out to be
  // the way out.
  const [mintedInstallUrl, setMintedInstallUrl] = useState<string | null>(null);
  const { toast } = useToast();

  const integrationId = integration?.id ?? null;
  const recordedChannels: SlackAuthorizedChannel[] =
    integration?.attributes.configuration.channels ?? [];

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
  // Local state needed: the picks are buffered until the user saves them.
  const [selectedChannelIds, setSelectedChannelIds] = useState<string[]>(
    recordedChannels.map((channel) => channel.id),
  );
  // Mirrored in state, not read from the prop, so channel-gated affordances
  // move on save instead of waiting for the revalidation.
  const [authorizedChannels, setAuthorizedChannels] =
    useState(recordedChannels);
  // The prop the mirror was last taken from: the card never unmounts, so a
  // mirror seeded only at mount would go stale when the record changes.
  const [syncedChannels, setSyncedChannels] = useState(recordedChannels);
  const [isSavingChannels, setIsSavingChannels] = useState(false);

  if (!sameChannelSets(recordedChannels, syncedChannels)) {
    const previousSyncedIds = syncedChannels.map((channel) => channel.id);
    setSyncedChannels(recordedChannels);
    setAuthorizedChannels(recordedChannels);
    // Follow the record only while the buffered picks still match it: an
    // unsaved pick is the user's, not ours to overwrite mid-edit.
    if (sameChannelIds(selectedChannelIds, previousSyncedIds)) {
      setSelectedChannelIds(recordedChannels.map((channel) => channel.id));
    }
  }

  // Only an answer from Slack moves the bus: a call that never got one proves
  // nothing and leaves the last answer standing.
  const provedCredentialAlive = () => setLastRefusalCode(null);

  const recordRefusal = (code: string | null | undefined) => {
    if (code) setLastRefusalCode(code);
  };

  /**
   * Whether the last refusal proves the grant itself is dead, rather than a
   * channel unreachable or Slack busy. Derived, not stored, so it self-clears:
   * a later call Slack answered at all (even to refuse a channel) is proof the
   * credential works again, and the notice goes with it.
   */
  const credentialFailure: SlackTokenErrorCode | null = isSlackTokenErrorCode(
    lastRefusalCode,
  )
    ? lastRefusalCode
    : null;

  const needsInstallUrl = disconnected || credentialFailure !== null;

  useEffect(() => {
    if (!needsInstallUrl) return;

    let cancelled = false;

    getSlackAuthorizeUrl()
      .then((result) => {
        if (cancelled || !("authorizeUrl" in result)) return;
        setMintedInstallUrl(result.authorizeUrl);
      })
      .catch(() => {
        // Nothing to say: the page loses a shortcut, not a way to reconnect.
      });

    return () => {
      cancelled = true;
    };
  }, [needsInstallUrl]);

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
        // The listing runs on arrival, so it is where a dead credential shows
        // up first. A read cut short still names its refusal's code, so a grant
        // that died on a later cursor page is heard too; a truncation naming
        // none was Slack busy, not refusing.
        if ("error" in result || result.code) recordRefusal(result.code);
        else provedCredentialAlive();
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

  const listedChannels =
    channelsState.status === CHANNELS_STATUS.LOADED
      ? channelsState.channels
      : [];
  const channelOptions = mergeChannelOptions(
    listedChannels,
    authorizedChannels,
  );

  // The check posts its confirmation only where none has landed yet, so these
  // are the channels the next one would post to (contract, Connection).
  const unconfirmedChannels = authorizedChannels.filter(
    (channel) => channel.confirmation_sent_at === null,
  );
  // Channels the buffered selection would drop. Removing one cascades into the
  // alert rules that target it, in the same transaction (design D11), so the
  // warning belongs to the pending save rather than to what is on record.
  const droppedChannels = authorizedChannels.filter(
    (channel) => !selectedChannelIds.includes(channel.id),
  );

  const checkHint = (): string => {
    if (authorizedChannels.length === 0) {
      return "Authorize at least one destination channel below to enable this check.";
    }
    return unconfirmedChannels.length > 0
      ? `Checks every authorized channel and posts “${CONFIRMATION_MESSAGE}” once to ${channelList(
          unconfirmedChannels.map((channel) => channel.name),
        )}.`
      : "Checks every authorized channel. Each was confirmed once already, so nothing is posted.";
  };

  const handleSaveChannels = async () => {
    if (!integrationId) return;

    let savedCount = 0;
    setIsSavingChannels(true);
    try {
      // Only ids travel — the API validates them and derives the names.
      const result = await setSlackAuthorizedChannels(
        integrationId,
        selectedChannelIds,
      );

      if ("error" in result) {
        // The API validates the channels against Slack, so the save can
        // discover the credential is gone.
        recordRefusal(result.code);
        toast({
          variant: "destructive",
          title: "Could not save the destination channels",
          description: result.error,
        });
        return;
      }

      // Prefer the API's own record: it derives the names (a channel renamed
      // in Slack since the list was read would otherwise show its old name)
      // and it is what says which channels are confirmed.
      const savedChannels =
        result.integration.attributes.configuration.channels ??
        recordedFromSelection(
          selectedChannelIds,
          channelOptions,
          authorizedChannels,
        );

      provedCredentialAlive();
      setAuthorizedChannels(savedChannels);
      setSelectedChannelIds(savedChannels.map((channel) => channel.id));
      savedCount = savedChannels.length;
      toast({
        title: "Destination channels saved",
        description:
          savedChannels.length > 0
            ? `Prowler will post to ${channelList(
                savedChannels.map((channel) => channel.name),
              )}.`
            : "No destination channels are authorized any more.",
      });
    } catch (_error) {
      toast({
        variant: "destructive",
        title: "Could not save the destination channels",
        description: "Something went wrong. Please try again.",
      });
    } finally {
      setIsSavingChannels(false);
    }

    // Recording destinations is what makes a check possible (design D7), and
    // the save alone only proves the API took the ids: the check is what
    // reaches each channel and confirms it. A save that cleared the set has
    // nothing to post to.
    if (savedCount > 0) await handleTestConnection(integrationId);
  };

  const handleTestConnection = async (id: string) => {
    setIsTesting(true);
    try {
      const result = await testIntegrationConnection(id);

      if (result.success) {
        provedCredentialAlive();
        toast({
          title: "Connection test successful!",
          description:
            result.message ||
            "Prowler can reach your Slack workspace and every authorized channel.",
        });
      } else {
        // A dead credential named here is not a failure checking again can
        // fix, so the reason is recorded and not only reported.
        const reason = result.error?.trim() || null;

        recordRefusal(asReasonCode(reason));

        const explanation = reason
          ? slackErrorMessage({ code: reason, detail: reason })
          : "Failed to reach your Slack workspace.";

        toast({
          variant: "destructive",
          title: "Connection test failed",
          // The failure names the channel it is about (design D7): the fix is
          // in Slack, on that channel, not on the integration as a whole.
          description: result.failedChannel
            ? `Slack refused #${result.failedChannel}: ${explanation}`
            : explanation,
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

  const handleDisconnect = async (id: string) => {
    const recordedWorkspace =
      integration?.attributes.configuration.team_name ?? null;
    const workspace = recordedWorkspace ?? "your Slack workspace";

    setIsDisconnecting(true);
    try {
      const result = await disconnectSlackIntegration(id);

      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Disconnect failed",
          description: result.error,
        });
        return;
      }

      const { revoked } = result.revocation;

      // The row is gone whatever Slack answered, so the page goes back to its
      // unconnected state either way, and a dead credential is moot once the
      // row it belonged to is gone.
      setDisconnected(true);
      setLastRefusalCode(null);
      // Only an explicit `false` sends the user to finish the job in Slack: an
      // unreported outcome is neither a failed revocation nor a confirmed one,
      // so it claims neither.
      setUnconfirmedRevocation(
        revoked === false ? { workspace: recordedWorkspace } : null,
      );

      if (revoked !== false) {
        toast({
          title: "Slack workspace disconnected",
          description:
            revoked === true
              ? `Prowler's access to ${workspace} has been revoked.`
              : `${workspace} is no longer connected to Prowler.`,
        });
      }
    } catch (_error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to disconnect Slack. Please try again.",
      });
    } finally {
      setIsDisconnecting(false);
      setIsDisconnectOpen(false);
    }
  };

  const workspaceName = integration?.attributes.configuration.team_name;
  const installUrl = mintedInstallUrl ?? authorizeUrl;

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

      <Modal
        open={isDisconnectOpen}
        onOpenChange={setIsDisconnectOpen}
        title="Disconnect Slack workspace"
        description={`Prowler will remove the integration, stop posting to ${workspaceName ?? "this workspace"}, and attempt to revoke its access at Slack. Connecting again means approving Prowler in Slack.`}
      >
        <div className="flex w-full justify-end gap-4">
          <Button
            type="button"
            variant="ghost"
            size="lg"
            disabled={isDisconnecting}
            onClick={() => setIsDisconnectOpen(false)}
          >
            Cancel
          </Button>

          <Button
            type="button"
            variant="destructive"
            size="lg"
            disabled={isDisconnecting}
            onClick={() => integration && handleDisconnect(integration.id)}
          >
            {!isDisconnecting && <Unplug size={20} />}
            {isDisconnecting ? "Disconnecting..." : "Disconnect workspace"}
          </Button>
        </div>
      </Modal>

      {loadError && (
        <Alert variant="error">
          <AlertTitle>Could not load your Slack integration</AlertTitle>
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      )}

      {unconfirmedRevocation && (
        <Alert variant="warning">
          <AlertTitle>
            Slack disconnected — remove Prowler&apos;s access in Slack
          </AlertTitle>
          <AlertDescription>
            The integration and the token Prowler had stored are gone from
            Prowler, so there is nothing to retry here. Slack did not confirm
            the revocation, so the Prowler app may still be installed in{" "}
            {unconfirmedRevocation.workspace ?? "the workspace"} — remove it
            from that workspace&apos;s Slack app settings.
          </AlertDescription>
        </Alert>
      )}

      {credentialFailure && (
        <Alert variant="error">
          <AlertTitle>
            Slack no longer accepts Prowler&apos;s access to{" "}
            {workspaceName ?? "this workspace"}
          </AlertTitle>
          {/* Each mapped sentence already ends in the thing that fixes it. */}
          <AlertDescription>
            {slackErrorMessage({ code: credentialFailure })} Until then, nothing
            Prowler sends will reach the workspace.
          </AlertDescription>
          {installUrl && (
            <div className="col-start-2 mt-3">
              <Button asChild size="sm">
                <a href={installUrl} rel="noopener noreferrer">
                  <SlackIcon size={16} />
                  Reconnect to Slack
                </a>
              </Button>
            </div>
          )}
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
      ) : integration && !disconnected ? (
        <Card variant="base">
          <CardHeader>
            <IntegrationCardHeader
              icon={<SlackIcon size={32} />}
              title={`Connected to ${workspaceName ?? "your Slack workspace"}`}
              subtitle="Prowler posts to this workspace only."
              connectionStatus={{
                // A dead token outranks the state the page was loaded with.
                connected:
                  credentialFailure === null
                    ? integration.attributes.connected
                    : false,
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
                <div className="flex items-center gap-2">
                  {/* The check reaches the authorized channels: the API
                      answers 400 while the set is empty. */}
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={
                      isTesting ||
                      isSavingChannels ||
                      authorizedChannels.length === 0
                    }
                    // What the control does — or why it cannot — travels with
                    // it: an explanation across the row reads as unrelated.
                    aria-describedby={CHECK_HINT_ID}
                    onClick={() => handleTestConnection(integration.id)}
                  >
                    <TestTube size={14} />
                    {isTesting ? "Testing..." : "Test connection"}
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    disabled={isDisconnecting}
                    onClick={() => setIsDisconnectOpen(true)}
                  >
                    <Unplug size={14} />
                    Disconnect
                  </Button>
                </div>
                <p
                  id={CHECK_HINT_ID}
                  className="max-w-prose text-xs text-gray-500 sm:text-right dark:text-gray-300"
                >
                  {checkHint()}
                </p>
              </div>
            </div>

            <div className="border-border-neutral-secondary mt-6 flex flex-col gap-4 border-t pt-6">
              <SlackChannelMultiSelect
                options={channelOptions}
                values={selectedChannelIds}
                onChange={setSelectedChannelIds}
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
                disabled={isSavingChannels}
              />

              {droppedChannels.length > 0 && (
                <Alert variant="warning" data-deauthorize-warning>
                  <AlertTitle>
                    Dropped channels leave your alert rules too
                  </AlertTitle>
                  <AlertDescription>
                    Saving this selection drops{" "}
                    {channelList(
                      droppedChannels.map((channel) => channel.name),
                    )}
                    . Every alert rule targeting a dropped channel stops
                    targeting it, and Prowler stops delivering there.
                    Notifications already delivered stay in Slack.
                  </AlertDescription>
                </Alert>
              )}

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                {/* The card's subtitle also starts "Prowler posts to", so the
                    recorded set is keyed for what reads it. */}
                <p
                  className="text-text-neutral-secondary text-xs"
                  data-authorized-channels
                >
                  {authorizedChannels.length > 0
                    ? `Prowler posts to ${channelList(
                        authorizedChannels.map((channel) => channel.name),
                      )}.`
                    : "No destination channels authorized yet."}
                </p>
                <Button
                  size="sm"
                  disabled={
                    sameChannelIds(
                      selectedChannelIds,
                      authorizedChannels.map((channel) => channel.id),
                    ) ||
                    isSavingChannels ||
                    isTesting
                  }
                  onClick={handleSaveChannels}
                >
                  {isSavingChannels ? "Saving..." : "Save channels"}
                </Button>
              </div>
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
              {installUrl ? (
                <Button asChild>
                  <a href={installUrl} rel="noopener noreferrer">
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
