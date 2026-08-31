"use client";

import { Lock, RefreshCw } from "lucide-react";

import { SlackInlineCode } from "@/components/integrations/slack/slack-inline-code";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Label,
} from "@/components/shadcn";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";
import type { SlackChannelOption } from "@/types/integrations";

const INVITE_HINT = (
  <>
    A private channel only appears here after someone invites{" "}
    <SlackInlineCode>@Prowler</SlackInlineCode> to it in Slack. Invite it, then
    refresh.
  </>
);

interface SlackChannelMultiSelectProps {
  options: SlackChannelOption[];
  values: string[];
  onChange: (channelIds: string[]) => void;
  isLoading?: boolean;
  /** Why the channels could not be read — Slack's own reason, when it gave one. */
  error?: string | null;
  /** Why the list is partial. Shown with the picker, not instead of it. */
  incompleteNotice?: string | null;
  onRefresh?: () => void;
  disabled?: boolean;
  id?: string;
  /** Element explaining the picker — a caller's reason for disabling it. */
  describedBy?: string;
}

const chipLabel = (option: SlackChannelOption) => (
  <span className="flex min-w-0 items-center gap-1">
    {option.is_private && (
      <>
        <Lock size={12} aria-hidden="true" />
        <span className="sr-only">Private</span>
      </>
    )}
    <span className="truncate">#{option.name}</span>
  </span>
);

/** Driven entirely by props (design D1) so any consumer can reuse it. */
export const SlackChannelMultiSelect = ({
  options,
  values,
  onChange,
  isLoading = false,
  error = null,
  incompleteNotice = null,
  onRefresh,
  disabled = false,
  id = "slack-channels",
  describedBy,
}: SlackChannelMultiSelectProps) => {
  const isEmpty = !isLoading && !error && options.length === 0;
  // `htmlFor` may only name an element that exists, and the trigger is only
  // rendered in the picker branch.
  const hasPicker = !error && !isEmpty;

  // A copy: the list belongs to the caller. Sorted here rather than upstream so
  // every consumer of the picker offers the same order.
  const listed = [...options].sort((left, right) =>
    left.name.localeCompare(right.name, undefined, {
      sensitivity: "base",
      numeric: true,
    }),
  );

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between gap-3">
        <Label htmlFor={hasPicker ? id : undefined}>Destination channels</Label>
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
            public channel, or invite @Prowler to a private one in Slack with{" "}
            <SlackInlineCode>/invite @Prowler</SlackInlineCode>, then refresh.
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
          <MultiSelect values={values} onValuesChange={onChange}>
            <MultiSelectTrigger
              id={id}
              aria-label="Destination channels"
              aria-describedby={describedBy}
              disabled={disabled || isLoading}
            >
              <MultiSelectValue
                placeholder={
                  isLoading ? "Reading channels..." : "Choose channels"
                }
              />
            </MultiSelectTrigger>
            <MultiSelectContent
              search={{
                placeholder: "Search channels",
                emptyMessage: "No channel matches that search.",
              }}
            >
              {listed.map((option) => (
                <MultiSelectItem
                  key={option.id}
                  value={option.id}
                  badgeLabel={chipLabel(option)}
                  // `value` is the id, so names match only via this keyword.
                  keywords={[option.name]}
                  // Name hook: the rendered label mixes it with a "Private"
                  // badge.
                  data-channel={option.name}
                >
                  <span className="min-w-0 truncate">#{option.name}</span>
                  {option.is_private && (
                    <Badge variant="tag" size="sm">
                      Private
                    </Badge>
                  )}
                </MultiSelectItem>
              ))}
            </MultiSelectContent>
          </MultiSelect>
        </>
      )}

      <p className="text-text-neutral-secondary text-xs">{INVITE_HINT}</p>
    </div>
  );
};
