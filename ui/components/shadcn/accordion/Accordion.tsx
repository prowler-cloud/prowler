"use client";

import { ChevronDown } from "lucide-react";
import { Children, ReactNode, useState } from "react";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import { cn } from "@/lib/utils";

export interface AccordionItemProps {
  key: string;
  title: ReactNode;
  subtitle?: ReactNode;
  content: ReactNode;
  items?: AccordionItemProps[];
  isDisabled?: boolean;
}

export interface AccordionProps {
  items: AccordionItemProps[];
  variant?: "light" | "shadow" | "bordered" | "splitted";
  className?: string;
  defaultExpandedKeys?: string[];
  selectedKeys?: string[];
  selectionMode?: "single" | "multiple";
  isCompact?: boolean;
  showDivider?: boolean;
  onItemExpand?: (key: string) => void;
  onSelectionChange?: (keys: string[]) => void;
}

const AccordionContent = ({
  content,
  items,
  selectedKeys,
  onSelectionChange,
}: {
  content: ReactNode;
  items?: AccordionItemProps[];
  selectedKeys?: string[];
  onSelectionChange?: (keys: string[]) => void;
}) => {
  // Normalize possible array content to automatically assign stable keys
  const normalizedContent = Array.isArray(content)
    ? Children.toArray(content)
    : content;

  return (
    <div className="text-text-neutral-secondary text-sm">
      {normalizedContent}
      {items && items.length > 0 && (
        <div className="border-border-neutral-secondary mt-4 ml-2 border-l-2 pl-4">
          <Accordion
            items={items}
            variant="light"
            isCompact
            selectionMode="multiple"
            selectedKeys={selectedKeys}
            onSelectionChange={onSelectionChange}
          />
        </div>
      )}
    </div>
  );
};

export const Accordion = ({
  items,
  variant = "light",
  className,
  defaultExpandedKeys = [],
  selectedKeys,
  selectionMode = "single",
  isCompact = false,
  showDivider = true,
  onItemExpand,
  onSelectionChange,
}: AccordionProps) => {
  // Determine if component is in controlled or uncontrolled mode
  const isControlled = selectedKeys !== undefined;

  const [internalExpandedKeys, setInternalExpandedKeys] =
    useState<string[]>(defaultExpandedKeys);

  // Use selectedKeys if controlled, otherwise use internal state
  const expandedKeys = isControlled ? selectedKeys : internalExpandedKeys;

  const handleToggle = (key: string, open: boolean) => {
    let nextKeys: string[];

    if (open) {
      // Single mode collapses siblings; multiple mode keeps the whole set so
      // nested accordions sharing the same controlled state don't wipe parents
      nextKeys = selectionMode === "multiple" ? [...expandedKeys, key] : [key];
      onItemExpand?.(key);
    } else {
      nextKeys = expandedKeys.filter((expandedKey) => expandedKey !== key);
    }

    if (isControlled) {
      onSelectionChange?.(nextKeys);
    } else {
      setInternalExpandedKeys(nextKeys);
    }
  };

  return (
    <div
      data-variant={variant}
      className={cn(
        "bg-bg-neutral-primary border-border-neutral-secondary w-full rounded-lg border",
        className,
      )}
    >
      {items.map((item, index) => {
        const isExpanded = expandedKeys.includes(item.key);

        return (
          <div key={item.key}>
            <Collapsible
              data-accordion-key={item.key}
              open={isExpanded}
              onOpenChange={(open) => handleToggle(item.key, open)}
              disabled={item.isDisabled}
              className="my-2"
            >
              <CollapsibleTrigger
                aria-label={
                  typeof item.title === "string"
                    ? item.title
                    : `Item ${item.key}`
                }
                className={cn(
                  "hover:bg-bg-neutral-tertiary data-[state=open]:bg-bg-neutral-tertiary flex w-full items-center rounded-lg px-2 transition-colors disabled:cursor-not-allowed disabled:opacity-50",
                  isCompact ? "py-1" : "py-2",
                )}
              >
                <div className="flex-1 text-left">
                  <div className="text-sm">{item.title}</div>
                  {item.subtitle && (
                    <div className="text-text-neutral-tertiary text-xs">
                      {item.subtitle}
                    </div>
                  )}
                </div>
                <ChevronDown
                  aria-hidden="true"
                  className={cn(
                    "text-text-neutral-tertiary shrink-0 transition-transform duration-200",
                    isExpanded && "rotate-180",
                  )}
                />
              </CollapsibleTrigger>
              <CollapsibleContent className="data-[state=closed]:animate-collapsible-up data-[state=open]:animate-collapsible-down overflow-hidden">
                <div className="px-0 py-1">
                  <AccordionContent
                    content={item.content}
                    items={item.items}
                    selectedKeys={selectedKeys}
                    onSelectionChange={onSelectionChange}
                  />
                </div>
              </CollapsibleContent>
            </Collapsible>
            {showDivider && index < items.length - 1 && (
              <div className="bg-border-neutral-secondary h-px w-full" />
            )}
          </div>
        );
      })}
    </div>
  );
};

Accordion.displayName = "Accordion";
