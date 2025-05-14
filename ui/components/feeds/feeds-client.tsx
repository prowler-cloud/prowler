"use client";

import Link from "next/link";
import { useState } from "react";

import { BellIcon as Icon } from "@/components/icons";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu/dropdown-menu";
import { cn } from "@/lib/utils";

import { Button } from "../ui/button/button";

interface Feed {
  title: string;
  link: string;
  description: string;
  lastBuildDate: string;
}

interface FeedsClientProps {
  initialFeeds?: Feed[];
}

// TODO: Need to update FeedsClientProps with actual interface when actual RSS data finialized
export const FeedsClient: React.FC<FeedsClientProps> = ({
  initialFeeds = [],
}) => {
  const [feed] = useState(initialFeeds);

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            className={cn(
              "relative",
              "rounded-full",
              "bg-transparent",
              "p-2",
              "h-8",
              "w-8",
            )}
          >
            <Icon size={18} />
            {/* TODO: Update this condition once the RSS data response structure is finalized */}
            {feed.length > 0 && (
              <span className="absolute right-0 top-0 h-2 w-2 rounded-full bg-red-500 dark:bg-gray-400"></span>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" forceMount>
          <h3 className="px-2 text-base font-medium">Feeds</h3>
          <div className="max-h-48 w-80 overflow-y-auto">
            {feed.length === 0 ? (
              <p className="py-4 text-center text-gray-500">
                No feeds available
              </p>
            ) : (
              feed.map((item, index) => (
                <DropdownMenuItem key={index} className="hover:cursor-pointer">
                  <Link
                    href={item.link}
                    target="_blank"
                    className="flex flex-col"
                  >
                    <h3 className="text-small font-medium leading-none">
                      {item.title}
                    </h3>
                    <p className="text-sm text-gray-500">{item.description}</p>
                    <span className="text-muted-foreground mt-1 text-xs text-gray-400">
                      {item.lastBuildDate}
                    </span>
                  </Link>
                </DropdownMenuItem>
              ))
            )}
          </div>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
};
