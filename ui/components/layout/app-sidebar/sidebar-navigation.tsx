"use client";

import { ArrowUpRight, ChevronDown } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import { ScrollArea } from "@/components/shadcn/scroll-area/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import { useCloudUpgradeStore } from "@/store";

import {
  type AppSidebarSelectionHandler,
  NAVIGATION_ITEM_KIND,
  type NavigationChild,
  type NavigationChildLink,
  type NavigationCloudUpgrade,
  type NavigationCollapsible,
  type NavigationLink,
  type NavigationSection,
} from "./types";

interface SidebarNavigationProps {
  sections: NavigationSection[];
  onSelect?: AppSidebarSelectionHandler;
}

interface NavigationLinkProps {
  item: NavigationLink;
  onSelect?: AppSidebarSelectionHandler;
}

interface NavigationCollapsibleProps {
  item: NavigationCollapsible;
  onSelect?: AppSidebarSelectionHandler;
}

interface NavigationChildProps {
  item: NavigationChild;
  onSelect?: AppSidebarSelectionHandler;
}

function TopLevelLink({ item, onSelect }: NavigationLinkProps) {
  const Icon = item.icon;
  const isExternal = item.target === "_blank";
  const link = (
    <Link
      href={item.href}
      target={item.target}
      rel={isExternal ? "noopener noreferrer" : undefined}
      aria-current={item.active ? "page" : undefined}
      onClick={onSelect}
      className={cn(
        "group focus-visible:ring-button-primary/50 relative flex min-h-10 w-full items-center gap-3 rounded-lg border px-3 py-2 text-sm font-medium transition-all duration-200 focus-visible:ring-2 focus-visible:outline-none",
        item.active
          ? "border-border-sidebar-active bg-bg-sidebar-active text-text-neutral-primary shadow-sidebar-active"
          : "text-text-neutral-secondary hover:border-border-sidebar-hover hover:bg-bg-sidebar-hover hover:text-text-neutral-primary border-transparent",
      )}
    >
      {item.active && (
        <span
          aria-hidden="true"
          className="bg-sidebar-active-bar absolute top-2 bottom-2 -left-px w-0.5 rounded-full"
        />
      )}
      <Icon
        aria-hidden="true"
        className={cn(
          "size-[18px] shrink-0",
          item.active && "text-sidebar-active-icon",
        )}
      />
      <span className="min-w-0 flex-1 truncate">{item.label}</span>
      {item.highlight && (
        <Badge variant="new" size="sm">
          New
        </Badge>
      )}
      {isExternal && <ArrowUpRight aria-hidden="true" className="size-4" />}
    </Link>
  );

  if (!item.tooltip) return link;

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{item.tooltip}</TooltipContent>
    </Tooltip>
  );
}

function CloudUpgradeChild({
  item,
  onSelect,
}: {
  item: NavigationCloudUpgrade;
  onSelect?: AppSidebarSelectionHandler;
}) {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <button
      type="button"
      className="text-text-neutral-secondary hover:bg-bg-sidebar-hover hover:text-text-neutral-primary focus-visible:ring-button-primary/50 flex min-h-8 w-full items-center gap-2 rounded-md px-3 py-1.5 text-left text-sm transition-colors focus-visible:ring-2 focus-visible:outline-none"
      onClick={() => {
        openCloudUpgrade(item.cloudUpgradeFeature, onSelect?.() ?? undefined);
      }}
    >
      <span className="min-w-0 flex-1 truncate">{item.label}</span>
      <Badge variant="cloud" size="sm">
        Cloud
      </Badge>
    </button>
  );
}

function LinkChild({
  item,
  onSelect,
}: {
  item: NavigationChildLink;
  onSelect?: AppSidebarSelectionHandler;
}) {
  const isExternal = item.target === "_blank";

  if (item.disabled) {
    return (
      <span className="text-text-neutral-tertiary flex min-h-8 items-center rounded-md px-3 py-1.5 text-sm">
        {item.label}
      </span>
    );
  }

  return (
    <Link
      href={item.href}
      target={item.target}
      rel={isExternal ? "noopener noreferrer" : undefined}
      aria-current={item.active ? "page" : undefined}
      onClick={onSelect}
      className={cn(
        "focus-visible:ring-button-primary/50 flex min-h-8 items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors focus-visible:ring-2 focus-visible:outline-none",
        item.active
          ? "bg-bg-sidebar-subitem-active text-text-neutral-primary font-medium"
          : "text-text-neutral-secondary hover:bg-bg-sidebar-hover hover:text-text-neutral-primary",
      )}
    >
      <span className="min-w-0 flex-1 truncate">{item.label}</span>
      {item.highlight && (
        <Badge variant="new" size="sm">
          New
        </Badge>
      )}
      {isExternal && <ArrowUpRight aria-hidden="true" className="size-3.5" />}
    </Link>
  );
}

function NavigationChildItem({ item, onSelect }: NavigationChildProps) {
  if (item.kind === NAVIGATION_ITEM_KIND.CLOUD_UPGRADE) {
    return <CloudUpgradeChild item={item} onSelect={onSelect} />;
  }

  return <LinkChild item={item} onSelect={onSelect} />;
}

function CollapsibleNavigationItem({
  item,
  onSelect,
}: NavigationCollapsibleProps) {
  const hasActiveChild = item.children.some(
    (child) =>
      child.kind === NAVIGATION_ITEM_KIND.LINK && child.active === true,
  );
  const [expanded, setExpanded] = useState(item.defaultOpen || hasActiveChild);
  const isOpen = hasActiveChild || expanded;
  const Icon = item.icon;

  return (
    <Collapsible open={isOpen} onOpenChange={setExpanded}>
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className={cn(
            "focus-visible:ring-button-primary/50 relative flex min-h-10 w-full items-center gap-3 rounded-lg border px-3 py-2 text-left text-sm font-medium transition-all duration-200 focus-visible:ring-2 focus-visible:outline-none",
            hasActiveChild
              ? "border-border-sidebar-active bg-bg-sidebar-active text-text-neutral-primary shadow-sidebar-active"
              : "text-text-neutral-secondary hover:bg-bg-sidebar-hover hover:text-text-neutral-primary border-transparent",
          )}
        >
          {hasActiveChild && (
            <span
              aria-hidden="true"
              className="bg-sidebar-active-bar absolute top-2 bottom-2 -left-px w-0.5 rounded-full"
            />
          )}
          <Icon
            aria-hidden="true"
            className={cn(
              "size-[18px] shrink-0",
              hasActiveChild && "text-sidebar-active-icon",
            )}
          />
          <span className="min-w-0 flex-1 truncate">{item.label}</span>
          <ChevronDown
            aria-hidden="true"
            className={cn(
              "size-4 transition-transform duration-200",
              isOpen && "rotate-180",
            )}
          />
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent className="data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down overflow-hidden">
        <ul className="border-sidebar-guide mt-1 ml-[21px] space-y-0.5 border-l pl-3">
          {item.children.map((child) => (
            <li key={child.label}>
              <NavigationChildItem item={child} onSelect={onSelect} />
            </li>
          ))}
        </ul>
      </CollapsibleContent>
    </Collapsible>
  );
}

function NavigationSectionList({
  section,
  onSelect,
}: {
  section: NavigationSection;
  onSelect?: AppSidebarSelectionHandler;
}) {
  return (
    <section
      aria-labelledby={section.label ? `sidebar-${section.label}` : undefined}
    >
      {section.label && (
        <h2
          id={`sidebar-${section.label}`}
          className="text-text-neutral-tertiary mb-1.5 px-3 text-[10px] font-semibold tracking-[0.14em]"
        >
          {section.label}
        </h2>
      )}
      <ul className="space-y-1">
        {section.items.map((item) => (
          <li key={item.label}>
            {item.kind === NAVIGATION_ITEM_KIND.COLLAPSIBLE ? (
              <CollapsibleNavigationItem item={item} onSelect={onSelect} />
            ) : (
              <TopLevelLink item={item} onSelect={onSelect} />
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function SidebarNavigation({
  sections,
  onSelect,
}: SidebarNavigationProps) {
  return (
    <ScrollArea className="h-full [&>div>div[style]]:block!">
      <nav aria-label="Main navigation" className="space-y-5 px-3 py-4">
        {sections.map((section, index) => (
          <NavigationSectionList
            key={section.label ?? `primary-${index}`}
            section={section}
            onSelect={onSelect}
          />
        ))}
      </nav>
    </ScrollArea>
  );
}
