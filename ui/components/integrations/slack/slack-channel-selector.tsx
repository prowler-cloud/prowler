"use client";

import { ChevronDown, RefreshCw } from "lucide-react";
import { useState } from "react";

import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Label,
} from "@/components/shadcn";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/shadcn/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
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
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState("");

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
  const selected = options.find((option) => option.id === value) ?? null;

  const handleOpenChange = (open: boolean) => {
    setIsOpen(open);
    // Drop the search with the popover, so re-opening it never starts filtered.
    if (!open) setQuery("");
  };

  const handleSelect = (channelId: string) => {
    onChange(channelId);
    handleOpenChange(false);
  };

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
          <Popover open={isOpen} onOpenChange={handleOpenChange}>
            <PopoverTrigger asChild>
              <Button
                id="slack-channel"
                variant="outline"
                size="lg"
                role="combobox"
                aria-expanded={isOpen}
                disabled={disabled || isLoading}
                className="w-full justify-between"
              >
                <span className="min-w-0 truncate">
                  {selected
                    ? `#${selected.name}`
                    : isLoading
                      ? "Reading channels..."
                      : "Choose a channel"}
                </span>
                <ChevronDown size={16} aria-hidden="true" />
              </Button>
            </PopoverTrigger>
            <PopoverContent
              align="start"
              className="w-(--radix-popover-trigger-width) p-0"
            >
              <Command>
                <CommandInput
                  placeholder="Search channels"
                  value={query}
                  onValueChange={setQuery}
                  aria-label="Search channels"
                />
                <CommandList>
                  {/* A workspace with no channels at all is a different
                      situation, answered by the alert above. */}
                  <CommandEmpty>No channel matches that search.</CommandEmpty>
                  <CommandGroup>
                    {listed.map((option) => (
                      <CommandItem
                        key={option.id}
                        // The search matches on this value, so it carries the
                        // name the user types; the id travels to `onChange`
                        // through the closure. A name can be empty on the wire.
                        value={option.name || option.id}
                        onSelect={() => handleSelect(option.id)}
                        // Name hook: the rendered label mixes it with a
                        // "Private" badge.
                        data-channel={option.name}
                      >
                        <span className="min-w-0 truncate">#{option.name}</span>
                        {option.is_private && (
                          <Badge variant="tag" size="sm">
                            Private
                          </Badge>
                        )}
                      </CommandItem>
                    ))}
                  </CommandGroup>
                </CommandList>
              </Command>
            </PopoverContent>
          </Popover>
        </>
      )}

      <p className="text-text-neutral-secondary text-xs">{INVITE_HINT}</p>
    </div>
  );
};
