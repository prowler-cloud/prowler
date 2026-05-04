"use client";

import { useEffect, useRef, useState } from "react";

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
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!scrollToKey || !containerRef.current) return;
    // Wait one frame so the accordion has applied the expanded state and
    // the target's final layout position is what we land on (HeroUI's
    // motion-driven expansion otherwise leaves us at the collapsed offset).
    const handle = requestAnimationFrame(() => {
      const node = containerRef.current?.querySelector(
        `[data-accordion-key="${CSS.escape(scrollToKey)}"]`,
      );
      if (node) {
        node.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
    return () => cancelAnimationFrame(handle);
  }, [scrollToKey, items]);

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
