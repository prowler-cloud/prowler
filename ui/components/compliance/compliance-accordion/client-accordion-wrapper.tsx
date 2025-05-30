"use client";

import { useState } from "react";

import { Accordion, AccordionItemProps } from "@/components/ui";
import { CustomButton } from "@/components/ui/custom";

export const ClientAccordionWrapper = ({
  items,
  defaultExpandedKeys,
}: {
  items: AccordionItemProps[];
  defaultExpandedKeys: string[];
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
    <div className="space-y-4">
      <div className="flex justify-end">
        <CustomButton
          variant="flat"
          size="sm"
          onPress={handleToggleExpand}
          ariaLabel={isExpanded ? "Collapse all" : "Expand all"}
        >
          {isExpanded ? "Collapse all" : "Expand all"}
        </CustomButton>
      </div>
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
