"use client";

import { Lock, RefreshCw } from "lucide-react";

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import type { SlackChannelOption } from "@/types/integrations";

/**
 * Picks a Slack channel out of the ones Prowler can post to.
 *
 * Deliberately self-contained (design D13): it knows nothing about the Slack
 * management page, nothing about server actions, and nothing about what the
 * chosen channel is going to be used for. Everything it renders comes from
 * props — the options, the current value, whether the list is still loading,
 * why it could not be loaded, and why what it does list may not be all of it —
 * so the alert-rule form can import it unchanged and drive it from its own
 * source of channels.
 *
 * The invite copy lives here rather than at the call site because it explains
 * *this control's* behaviour: `groups:read` is membership-gated, so a private
 * channel is missing from the list until someone in Slack invites the Prowler
 * app to it. Every consumer of the picker owes the user that sentence.
 */

const INVITE_HINT =
  "A private channel only appears here after someone invites @Prowler to it in Slack. Invite it, then refresh.";

interface SlackChannelSelectorProps {
  /** Channels Prowler can post to, each flagged as public or private. */
  options: SlackChannelOption[];
  /** The channel currently chosen, or null when none is. */
  value: string | null;
  onChange: (channelId: string) => void;
  /** The options are still being read from the workspace. */
  isLoading?: boolean;
  /** Why the channels could not be read — Slack's own reason, when it gave one. */
  error?: string | null;
  /**
   * Why the options are only part of the workspace's channels. Shown with the
   * picker, not instead of it: the list works, it is just not the whole
   * workspace.
   */
  incompleteNotice?: string | null;
  /** Offered beside the picker when the caller can re-read the channels. */
  onRefresh?: () => void;
  disabled?: boolean;
}

export const SlackChannelSelector = ({
  options,
  value,
  onChange,
  isLoading = false,
  error = null,
  incompleteNotice = null,
  onRefresh,
  disabled = false,
}: SlackChannelSelectorProps) => {
  const isEmpty = !isLoading && !error && options.length === 0;
  // The trigger only exists in the picker branch, so the label only points at
  // something there: an `htmlFor` naming a missing element is invalid markup.
  const hasPicker = !error && !isEmpty;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-3">
        <Label htmlFor={hasPicker ? "slack-channel" : undefined}>
          Destination channel
        </Label>
        {onRefresh && (
          <Button
            size="sm"
            variant="outline"
            disabled={isLoading}
            onClick={onRefresh}
          >
            <RefreshCw size={14} />
            {isLoading ? "Refreshing..." : "Refresh channels"}
          </Button>
        )}
      </div>

      {error ? (
        <Alert variant="error">
          <AlertTitle>Could not read the workspace&apos;s channels</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : isEmpty ? (
        <Alert variant="info">
          <AlertTitle>No channels available yet</AlertTitle>
          <AlertDescription>
            Prowler cannot see a single channel in this workspace. Create a
            public channel, or invite @Prowler to a private one in Slack with
            <span className="font-medium"> /invite @Prowler</span>, then
            refresh.
          </AlertDescription>
        </Alert>
      ) : (
        <>
          {/* Above the picker, and an alert rather than a hint: it qualifies
              the options the user is about to read, and the invite copy under
              them is a standing instruction that explains nothing about it. */}
          {incompleteNotice && (
            <Alert variant="warning" data-channels-notice>
              <AlertTitle>Not every channel is listed</AlertTitle>
              <AlertDescription>{incompleteNotice}</AlertDescription>
            </Alert>
          )}
          <Select
            value={value ?? undefined}
            onValueChange={onChange}
            disabled={disabled || isLoading}
          >
            <SelectTrigger id="slack-channel" size="sm">
              <SelectValue
                placeholder={
                  isLoading ? "Reading channels..." : "Choose a channel"
                }
              />
            </SelectTrigger>
            <SelectContent>
              {options.map((option) => (
                <SelectItem
                  key={option.id}
                  value={option.id}
                  // The label mixes the name with a lock and a "Private"
                  // marker, so the name gets its own hook rather than being
                  // parsed back out of the rendered text.
                  data-channel={option.name}
                >
                  {option.is_private && <Lock size={14} aria-hidden="true" />}
                  <span className="min-w-0 truncate">#{option.name}</span>
                  {option.is_private && (
                    <Badge variant="tag" size="sm">
                      Private
                    </Badge>
                  )}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </>
      )}

      <p className="text-text-neutral-secondary text-xs">{INVITE_HINT}</p>
    </div>
  );
};
