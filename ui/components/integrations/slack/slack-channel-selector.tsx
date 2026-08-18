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

const INVITE_HINT =
  "A private channel only appears here after someone invites @Prowler to it in Slack. Invite it, then refresh.";

interface SlackChannelSelectorProps {
  options: SlackChannelOption[];
  value: string | null;
  onChange: (channelId: string) => void;
  isLoading?: boolean;
  /** Why the channels could not be read — Slack's own reason, when it gave one. */
  error?: string | null;
  /** Why the list is partial. Shown with the picker, not instead of it. */
  incompleteNotice?: string | null;
  onRefresh?: () => void;
  disabled?: boolean;
}

/** Driven entirely by props (design D13) so the alert-rule form can reuse it. */
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
  // `htmlFor` may only name an element that exists, and the trigger is only
  // rendered in the picker branch.
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
                  // Name hook: the rendered label mixes it with a lock icon
                  // and a "Private" badge.
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
