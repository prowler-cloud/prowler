"use client";

import {
  Accordion as NextUIAccordion,
  AccordionItem,
  Selection,
} from "@nextui-org/react";
import { ChevronDown } from "lucide-react";
import React, { ReactNode, useCallback, useState } from "react";

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
  selectionMode?: "single" | "multiple";
  isCompact?: boolean;
  showDivider?: boolean;
  onItemExpand?: (key: string) => void;
}

const AccordionContent = ({
  content,
  items,
}: {
  content: ReactNode;
  items?: AccordionItemProps[];
}) => {
  return (
    <div className="overflow-x-auto text-sm text-gray-700 dark:text-gray-300">
      {content}
      {items && items.length > 0 && (
        <div className="ml-2 mt-4 border-l-2 border-gray-200 pl-4 dark:border-gray-700">
          <Accordion
            items={items}
            variant="light"
            isCompact
            selectionMode="multiple"
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
  selectionMode = "single",
  isCompact = false,
  showDivider = true,
  onItemExpand,
}: AccordionProps) => {
  const [expandedKeys, setExpandedKeys] = useState<Selection>(
    new Set(defaultExpandedKeys),
  );

  const handleSelectionChange = useCallback(
    (keys: Selection) => {
      if (onItemExpand && keys !== expandedKeys) {
        const currentKeys = Array.from(expandedKeys as Set<string>);
        const newKeys = Array.from(keys as Set<string>);

        const newlyExpandedKeys = newKeys.filter(
          (key) => !currentKeys.includes(key),
        );

        newlyExpandedKeys.forEach((key) => {
          onItemExpand(key);
        });
      }

      setExpandedKeys(keys);
    },
    [expandedKeys, onItemExpand],
  );

  return (
    <NextUIAccordion
      className={cn("w-full", className)}
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
            base: index === 0 || index === 1 ? "my-2" : "my-1",
            title: "text-sm font-medium max-w-full overflow-hidden truncate",
            subtitle: "text-xs text-gray-500",
            trigger:
              "p-2 rounded-lg data-[hover=true]:bg-gray-50 dark:data-[hover=true]:bg-gray-800/50 w-full flex items-center overflow-hidden",
            content: "p-2 overflow-x-auto",
          }}
        >
          <AccordionContent content={item.content} items={item.items} />
        </AccordionItem>
      ))}
    </NextUIAccordion>
  );
};

Accordion.displayName = "Accordion";
