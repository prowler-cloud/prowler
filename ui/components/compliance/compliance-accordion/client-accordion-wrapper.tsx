"use client";

import { useRef, useState } from "react";

import { Button } from "@/components/shadcn";
import { Accordion, AccordionItemProps } from "@/components/ui";

export const ClientAccordionWrapper = ({
  items,
  defaultExpandedKeys,
  hideExpandButton = false,
  scrollToKey,
}: {
  items: AccordionItemProps[];
  defaultExpandedKeys: string[];
  hideExpandButton?: boolean;
  scrollToKey?: string;
}) => {
  const [selectedKeys, setSelectedKeys] =
    useState<string[]>(defaultExpandedKeys);
  const [isExpanded, setIsExpanded] = useState(false);

  // Function to get all keys except the last level (requirements)
  const getAllKeysExceptLastLevel = (items: AccordionItemProps[]): string[] => {
    const keys: string[] = [];

    const traverse = (items: AccordionItemProps[], level: number = 0) => {
      items.forEach((item) => {
        // Add current item key if it's not the last level
        if (item.items && item.items.length > 0) {
          keys.push(item.key);
          // Check if the children have their own children (not the last level)
          const hasGrandChildren = item.items.some(
            (child) => child.items && child.items.length > 0,
          );
          if (hasGrandChildren) {
            traverse(item.items, level + 1);
          }
        }
      });
    };

    traverse(items);
    return keys;
  };

  const handleToggleExpand = () => {
    if (isExpanded) {
      setSelectedKeys(defaultExpandedKeys);
    } else {
      const allKeys = getAllKeysExceptLastLevel(items);
      setSelectedKeys(allKeys);
    }
    setIsExpanded(!isExpanded);
  };

  const handleSelectionChange = (keys: string[]) => {
    setSelectedKeys(keys);
  };

  // Tracks the last `scrollToKey` we already scrolled to so the inline
  // callback ref below stays idempotent. Without this flag React would
  // re-fire the scroll on every state change (Expand all, row toggle,
  // parent re-render) because the callback ref's identity changes per
  // render and React re-attaches it.
  const lastScrolledKeyRef = useRef<string | null>(null);

  const containerRef = (node: HTMLDivElement | null) => {
    if (!node || !scrollToKey) return;
    if (lastScrolledKeyRef.current === scrollToKey) return;
    lastScrolledKeyRef.current = scrollToKey;
    // Two nested rAFs: the first lets the accordion children commit to
    // the DOM, the second lands after the browser has run a layout pass
    // so HeroUI's framer-motion expand has settled enough for
    // scrollIntoView to read a stable offset.
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        const target = node.querySelector(
          `[data-accordion-key="${CSS.escape(scrollToKey)}"]`,
        );
        target?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  };

  return (
    <div ref={containerRef}>
      {!hideExpandButton && (
        <div className="text-text-neutral-tertiary hover:text-text-neutral-primary mt-[-16px] flex justify-end text-xs font-medium transition-colors">
          <Button
            onClick={handleToggleExpand}
            aria-label={isExpanded ? "Collapse all" : "Expand all"}
            variant="ghost"
            size="sm"
            className="mb-1"
          >
            {isExpanded ? "Collapse all" : "Expand all"}
          </Button>
        </div>
      )}
      <Accordion
        items={items}
        variant="light"
        selectionMode="multiple"
        selectedKeys={selectedKeys}
        onSelectionChange={handleSelectionChange}
      />
    </div>
  );
};
