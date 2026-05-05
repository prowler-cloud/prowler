"use client";

import { useState } from "react";

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

  // Callback ref runs after the container's children have committed to the
  // DOM, so we can locate the target accordion item without an effect. The
  // rAF defers one frame so HeroUI's expand animation has applied the final
  // layout offset before scrollIntoView lands.
  const containerRef = (node: HTMLDivElement | null) => {
    if (!node || !scrollToKey) return;
    requestAnimationFrame(() => {
      const target = node.querySelector(
        `[data-accordion-key="${CSS.escape(scrollToKey)}"]`,
      );
      target?.scrollIntoView({ behavior: "smooth", block: "start" });
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
