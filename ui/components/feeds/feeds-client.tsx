"use client";

import { formatDistanceToNow, parseISO } from "date-fns";
import { BellRing, ExternalLink } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import type { FeedItem, ParsedFeed } from "@/actions/feeds";
import { Badge } from "@/components/shadcn";
import { Separator } from "@/components/shadcn";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu/dropdown-menu";
import { hasNewFeeds, markFeedsAsSeen } from "@/lib/feeds-storage";
import { cn } from "@/lib/utils";

import { Button } from "../ui/button/button";

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
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          className="relative h-8 w-8 rounded-full bg-transparent p-2"
        >
          <BellRing
            size={18}
            className={cn(
              hasFeeds && hasUnseenFeeds && "animate-pulse text-[#86da26]",
            )}
          />
          {hasFeeds && hasUnseenFeeds && (
            <span className="absolute top-0 right-0 flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#86da26] opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[#86da26]"></span>
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent
        align="end"
        className="w-96 overflow-x-hidden"
        forceMount
      >
        <div className="px-3 py-2">
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
        <div
          className={cn(
            "z-10 h-2 w-2 rounded-full border-2",
            item.source.type === "github_releases"
              ? "border-[#86da26] bg-[#86da26]"
              : "border-[#86da26] bg-[#86da26]",
          )}
        />
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
          className="block space-y-1 rounded-lg p-2 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800"
        >
          <div className="flex items-start justify-between gap-2">
            <h4 className="min-w-0 flex-1 text-sm leading-tight font-semibold break-words text-slate-900 group-hover:text-[#86da26] dark:text-white dark:group-hover:text-[#86da26]">
              {item.title}
            </h4>
            {version && (
              <Badge
                variant="secondary"
                className="shrink-0 border-[#86da26] bg-[#86da26]/10 text-[10px] font-semibold text-[#86da26] dark:bg-[#86da26]/20"
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

            <div className="flex items-center gap-1 text-[#86da26] opacity-0 transition-opacity group-hover:opacity-100">
              <span className="text-[11px] font-medium">Read more</span>
              <ExternalLink size={10} />
            </div>
          </div>
        </Link>
      </div>
    </div>
  );
}
