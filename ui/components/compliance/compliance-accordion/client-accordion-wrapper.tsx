"use client";

import { useState } from "react";

import { Accordion, AccordionItemProps } from "@/components/ui";

export const ClientAccordionWrapper = ({
  items,
  defaultExpandedKeys,
  hideExpandButton = false,
}: {
  items: AccordionItemProps[];
  defaultExpandedKeys: string[];
  hideExpandButton?: boolean;
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

  return (
    <div>
      {!hideExpandButton && (
        <div className="mt-[-16px] flex justify-end text-xs font-medium text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300">
          <button
            onClick={handleToggleExpand}
            aria-label={isExpanded ? "Collapse all" : "Expand all"}
          >
            {isExpanded ? "Collapse all" : "Expand all"}
          </button>
        </div>
      )}
      <Accordion
        items={items}
        variant="light"
        selectionMode="multiple"
        defaultExpandedKeys={defaultExpandedKeys}
        selectedKeys={selectedKeys}
        onSelectionChange={handleSelectionChange}
      />
    </div>
  );
};
