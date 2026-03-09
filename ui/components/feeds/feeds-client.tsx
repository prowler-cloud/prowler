"use client";

import { formatDistanceToNow, parseISO } from "date-fns";
import { BellRing, ExternalLink } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import type { FeedItem, ParsedFeed } from "@/actions/feeds";
import {
  Badge,
  Button,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  Separator,
} from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { hasNewFeeds, markFeedsAsSeen } from "@/lib/feeds-storage";
import { cn } from "@/lib/utils";

interface FeedsClientProps {
  feedData: ParsedFeed;
  error?: string;
}

export function FeedsClient({ feedData, error }: FeedsClientProps) {
  const { items, totalCount } = feedData;
  const hasFeeds = totalCount > 0 && !error;

  // State to track if there are new unseen feeds
  const [hasUnseenFeeds, setHasUnseenFeeds] = useState(false);

  // Check for new feeds on mount
  useEffect(() => {
    if (hasFeeds) {
      const currentFeedIds = items.map((item) => item.id);
      const isNew = hasNewFeeds(currentFeedIds);
      setHasUnseenFeeds(isNew);
    }
  }, [hasFeeds, items]);

  // Mark feeds as seen when dropdown opens
  const handleOpenChange = (open: boolean) => {
    if (open && hasFeeds) {
      const currentFeedIds = items.map((item) => item.id);
      markFeedsAsSeen(currentFeedIds);
      setHasUnseenFeeds(false);
    }
  };

  return (
    <DropdownMenu onOpenChange={handleOpenChange}>
      <Tooltip>
        <TooltipTrigger asChild>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              className="border-border-input-primary-fill relative h-8 w-8 rounded-full bg-transparent p-2"
              aria-label={
                hasUnseenFeeds
                  ? "New updates available - Click to view"
                  : "Check for updates"
              }
            >
              <BellRing
                size={18}
                className={cn(
                  hasFeeds &&
                    hasUnseenFeeds &&
                    "text-button-primary animate-pulse",
                )}
              />
              {hasFeeds && hasUnseenFeeds && (
                <span className="absolute top-0 right-0 flex h-2 w-2">
                  <span className="bg-button-primary absolute inline-flex h-full w-full animate-ping rounded-full opacity-75"></span>
                  <span className="bg-button-primary relative inline-flex h-2 w-2 rounded-full"></span>
                </span>
              )}
            </Button>
          </DropdownMenuTrigger>
        </TooltipTrigger>
        <TooltipContent>
          {hasUnseenFeeds ? "New updates available" : "Latest Updates"}
        </TooltipContent>
      </Tooltip>

      <DropdownMenuContent
        align="end"
        className="w-96 gap-2 overflow-x-hidden border-slate-200 bg-white px-[18px] pt-3 pb-4 dark:border-zinc-900 dark:bg-stone-950"
      >
        <div className="pb-2">
          <h3 className="text-base font-semibold text-slate-900 dark:text-white">
            Latest Updates
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Recent releases and announcements
          </p>
        </div>

        <Separator />

        <div className="minimal-scrollbar max-h-[500px] overflow-x-hidden overflow-y-auto">
          {error && (
            <div className="px-3 py-8 text-center">
              <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
            </div>
          )}

          {!error && items.length === 0 && (
            <div className="px-3 py-8 text-center">
              <BellRing className="mx-auto mb-2 h-8 w-8 text-slate-400" />
              <p className="text-sm font-medium text-slate-600 dark:text-slate-300">
                No updates available
              </p>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Check back later for new releases
              </p>
            </div>
          )}

          {hasFeeds && (
            <div className="relative py-2">
              {items.map((item, index) => (
                <FeedTimelineItem
                  key={item.id}
                  item={item}
                  isLast={index === items.length - 1}
                />
              ))}
            </div>
          )}
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

interface FeedTimelineItemProps {
  item: FeedItem;
  isLast: boolean;
}

function FeedTimelineItem({ item, isLast }: FeedTimelineItemProps) {
  const relativeTime = formatDistanceToNow(parseISO(item.pubDate), {
    addSuffix: true,
  });

  // Extract version from title if it's a GitHub release
  const versionMatch = item.title.match(/v?(\d+\.\d+\.\d+)/);
  const version = versionMatch ? versionMatch[1] : null;

  return (
    <div className="group relative flex gap-3 px-3 py-2">
      {/* Timeline dot */}
      <div className="relative flex flex-col items-center">
        <div className="border-button-primary bg-button-primary z-10 h-2 w-2 rounded-full border-2" />
        {!isLast && (
          <div className="h-full w-px bg-slate-200 dark:bg-slate-700" />
        )}
      </div>

      {/* Content */}
      <div className="min-w-0 flex-1 pb-4">
        <Link
          href={item.link}
          target="_blank"
          rel="noopener noreferrer"
          className="backdrop-blur-0 block space-y-1 rounded-[12px] border border-transparent p-2 transition-all hover:border-slate-300 hover:bg-[#F8FAFC80] hover:backdrop-blur-[46px] dark:hover:border-[rgba(38,38,38,0.70)] dark:hover:bg-[rgba(23,23,23,0.50)]"
        >
          <div className="flex items-start justify-between gap-2">
            <h4 className="group-hover:text-button-primary dark:group-hover:text-button-primary min-w-0 flex-1 text-sm leading-tight font-semibold break-words text-slate-900 dark:text-white">
              {item.title}
            </h4>
            {version && (
              <Badge
                variant="secondary"
                className="border-button-primary bg-button-primary/10 text-button-primary dark:bg-button-primary/20 shrink-0 text-[10px] font-semibold"
              >
                v{version}
              </Badge>
            )}
          </div>

          {item.description && (
            <p className="line-clamp-2 text-xs leading-relaxed break-words text-slate-600 dark:text-slate-400">
              {item.description}
            </p>
          )}

          <div className="flex items-center justify-between pt-1">
            <time className="text-[11px] text-slate-500 dark:text-slate-500">
              {relativeTime}
            </time>

            <div className="text-button-primary flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
              <span className="text-[11px] font-medium">Read more</span>
              <ExternalLink size={10} />
            </div>
          </div>
        </Link>
      </div>
    </div>
  );
}
