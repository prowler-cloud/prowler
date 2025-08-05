"use client";

import {
  Accordion as NextUIAccordion,
  AccordionItem,
  Selection,
} from "@nextui-org/react";
import { ChevronDown } from "lucide-react";
import React, { ReactNode, useCallback, useMemo, useState } from "react";

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
  return (
    <div className="text-sm text-gray-700 dark:text-gray-300">
      {content}
      {items && items.length > 0 && (
        <div className="ml-2 mt-4 border-l-2 border-gray-200 pl-4 dark:border-gray-700">
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

  const [internalExpandedKeys, setInternalExpandedKeys] = useState<Selection>(
    new Set(defaultExpandedKeys),
  );

  // Use selectedKeys if controlled, otherwise use internal state
  const expandedKeys = useMemo(
    () => (isControlled ? new Set(selectedKeys) : internalExpandedKeys),
    [isControlled, selectedKeys, internalExpandedKeys],
  );

  const handleSelectionChange = useCallback(
    (keys: Selection) => {
      const keysArray = Array.from(keys as Set<string>);

      // If controlled mode, call parent callback
      if (isControlled && onSelectionChange) {
        onSelectionChange(keysArray);
      } else {
        // If uncontrolled, update internal state
        setInternalExpandedKeys(keys);
      }

      // Handle onItemExpand for backward compatibility
      if (onItemExpand && keys !== expandedKeys) {
        const currentKeys = Array.from(expandedKeys as Set<string>);
        const newKeys = keysArray;

        const newlyExpandedKeys = newKeys.filter(
          (key) => !currentKeys.includes(key),
        );

        newlyExpandedKeys.forEach((key) => {
          onItemExpand(key);
        });
      }
    },
    [expandedKeys, onItemExpand, isControlled, onSelectionChange],
  );

  return (
    <NextUIAccordion
      className={cn("w-full !px-0", className)}
      variant={variant}
      selectionMode={selectionMode}
      selectedKeys={expandedKeys}
      onSelectionChange={handleSelectionChange}
      isCompact={isCompact}
      showDivider={showDivider}
    >
      {items.map((item, index) => (
        <AccordionItem
          key={item.key}
          aria-label={
            typeof item.title === "string" ? item.title : `Item ${item.key}`
          }
          title={item.title}
          subtitle={item.subtitle}
          isDisabled={item.isDisabled}
          indicator={<ChevronDown className="text-gray-500" />}
          classNames={{
            base: index === 0 || index === 1 ? "my-1" : "my-1",
            title: "text-sm",
            subtitle: "text-xs text-gray-500",
            trigger:
              "py-2 px-2 rounded-lg data-[hover=true]:bg-gray-50 dark:data-[hover=true]:bg-gray-800/50 w-full flex items-center",
            content: "px-0 py-1",
          }}
        >
          <AccordionContent
            content={item.content}
            items={item.items}
            selectedKeys={selectedKeys}
            onSelectionChange={onSelectionChange}
          />
        </AccordionItem>
      ))}
    </NextUIAccordion>
  );
};

Accordion.displayName = "Accordion";
