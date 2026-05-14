"use client";

import { ChevronDown, XCircle, XIcon } from "lucide-react";
import { type ReactNode, useEffect, useId, useRef, useState } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/shadcn/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
import { Separator } from "@/components/shadcn/separator/separator";
import { cn } from "@/lib/utils";

interface MultiSelectOption {
  label: string;
  value: string;
  icon?: ReactNode;
  description?: string;
  disabled?: boolean;
}

interface EnhancedMultiSelectProps {
  options: MultiSelectOption[];
  onValueChange: (values: string[]) => void;
  defaultValue?: string[];
  placeholder?: string;
  searchable?: boolean;
  hideSelectAll?: boolean;
  maxCount?: number;
  closeOnSelect?: boolean;
  resetOnDefaultValueChange?: boolean;
  emptyIndicator?: ReactNode;
  disabled?: boolean;
  className?: string;
  id?: string;
  "aria-label"?: string;
}

function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((val, index) => val === sortedB[index]);
}

export function EnhancedMultiSelect({
  options,
  onValueChange,
  defaultValue = [],
  placeholder = "Select options",
  searchable = true,
  hideSelectAll = false,
  maxCount = 3,
  closeOnSelect = false,
  resetOnDefaultValueChange = true,
  emptyIndicator,
  disabled = false,
  className,
  id,
  "aria-label": ariaLabel,
}: EnhancedMultiSelectProps) {
  const [selectedValues, setSelectedValues] = useState<string[]>(defaultValue);
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [portalContainer, setPortalContainer] = useState<HTMLElement | null>(
    null,
  );

  const buttonRef = useRef<HTMLButtonElement>(null);
  const prevDefaultValueRef = useRef<string[]>(defaultValue);
  const selectedAtOpenRef = useRef<string[]>(selectedValues);
  const multiSelectId = useId();
  const listboxId = `${multiSelectId}-listbox`;

  // Detect dialog container for portal stacking (critical for Jira modal)
  useEffect(() => {
    if (!buttonRef.current) return;
    const closestDialogContainer = buttonRef.current.closest(
      "[data-slot='dialog-content'], [data-slot='modal-content'], [role='dialog']",
    );
    setPortalContainer(
      closestDialogContainer instanceof HTMLElement
        ? closestDialogContainer
        : null,
    );
  }, []);

  // Reset when defaultValue changes externally (e.g. React Hook Form reset)
  useEffect(() => {
    if (!resetOnDefaultValueChange) return;
    const prev = prevDefaultValueRef.current;
    if (!arraysEqual(prev, defaultValue)) {
      if (!arraysEqual(selectedValues, defaultValue)) {
        setSelectedValues(defaultValue);
      }
      prevDefaultValueRef.current = [...defaultValue];
    }
  }, [defaultValue, selectedValues, resetOnDefaultValueChange]);

  function handleOpenChange(nextOpen: boolean) {
    if (nextOpen) {
      selectedAtOpenRef.current = [...selectedValues];
    } else {
      setSearch("");
    }
    setOpen(nextOpen);
  }

  const enabledOptions = options.filter((o) => !o.disabled);

  const filteredOptions = (
    searchable && search
      ? options.filter(
          (o) =>
            o.label.toLowerCase().includes(search.toLowerCase()) ||
            o.value.toLowerCase().includes(search.toLowerCase()),
        )
      : options
  ).toSorted((a, b) => {
    const snapshot = selectedAtOpenRef.current;
    const aSelected = snapshot.includes(a.value) ? 0 : 1;
    const bSelected = snapshot.includes(b.value) ? 0 : 1;
    return aSelected - bSelected;
  });

  function getOptionByValue(value: string) {
    return options.find((o) => o.value === value);
  }

  function toggleOption(value: string) {
    if (disabled) return;
    const option = getOptionByValue(value);
    if (option?.disabled) return;
    const next = selectedValues.includes(value)
      ? selectedValues.filter((v) => v !== value)
      : [...selectedValues, value];
    setSelectedValues(next);
    onValueChange(next);
    if (closeOnSelect) setOpen(false);
  }

  function toggleAll() {
    if (disabled) return;
    if (selectedValues.length === enabledOptions.length) {
      handleClear();
    } else {
      const all = enabledOptions.map((o) => o.value);
      setSelectedValues(all);
      onValueChange(all);
    }
    if (closeOnSelect) setOpen(false);
  }

  function handleClear() {
    if (disabled) return;
    setSelectedValues([]);
    onValueChange([]);
  }

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          ref={buttonRef}
          variant="outline"
          onClick={() => !disabled && setOpen((prev) => !prev)}
          disabled={disabled}
          role="combobox"
          aria-expanded={open}
          aria-haspopup="listbox"
          aria-controls={open ? listboxId : undefined}
          aria-label={ariaLabel}
          className={cn(
            "border-border-input-primary bg-bg-input-primary text-text-neutral-primary data-[placeholder]:text-text-neutral-tertiary [&_svg:not([class*='text-'])]:text-text-neutral-tertiary aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive hover:bg-bg-input-primary active:bg-bg-input-primary focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press flex h-auto min-h-12 w-full items-center justify-between gap-2 rounded-lg border px-3 py-2 text-sm shadow-xs transition-[color,box-shadow] outline-none focus-visible:ring-1 focus-visible:ring-offset-1 [&_svg]:pointer-events-auto",
            disabled && "cursor-not-allowed opacity-50",
            className,
          )}
        >
          {selectedValues.length > 0 ? (
            <div className="flex w-full items-center justify-between">
              <div className="flex flex-wrap items-center gap-1">
                {selectedValues
                  .slice(0, maxCount)
                  .map((value) => {
                    const option = getOptionByValue(value);
                    if (!option) return null;
                    return (
                      <Badge
                        key={value}
                        variant="tag"
                        className="m-1 cursor-default [&>svg]:pointer-events-auto"
                      >
                        <span className="cursor-default">{option.label}</span>
                        <span
                          onMouseDown={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                          }}
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleOption(value);
                          }}
                          aria-label={`Remove ${option.label} from selection`}
                          className="focus:ring-border-input-primary-press -m-0.5 ml-2 inline-flex h-4 w-4 shrink-0 cursor-pointer items-center justify-center self-center rounded-sm p-0.5 focus:ring-1 focus:outline-none"
                        >
                          <XCircle className="h-3 w-3" />
                        </span>
                      </Badge>
                    );
                  })
                  .filter(Boolean)}
                {selectedValues.length > maxCount && (
                  <Badge
                    variant="tag"
                    className="m-1 cursor-default [&>svg]:pointer-events-auto"
                  >
                    {`+ ${selectedValues.length - maxCount} more`}
                    <span
                      onMouseDown={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                      }}
                      onClick={(e) => {
                        e.stopPropagation();
                        const trimmed = selectedValues.slice(0, maxCount);
                        setSelectedValues(trimmed);
                        onValueChange(trimmed);
                      }}
                      className="ml-2 inline-flex h-4 w-4 shrink-0 cursor-pointer items-center justify-center self-center rounded-sm"
                      aria-label="Clear extra selected options"
                    >
                      <XCircle className="h-3 w-3" />
                    </span>
                  </Badge>
                )}
              </div>
              <div className="flex items-center justify-between">
                <div
                  role="button"
                  tabIndex={0}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleClear();
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      e.stopPropagation();
                      handleClear();
                    }
                  }}
                  aria-label={`Clear all ${selectedValues.length} selected options`}
                  className="text-text-neutral-tertiary hover:text-text-neutral-primary focus:ring-border-input-primary-press mx-2 flex h-4 w-4 cursor-pointer items-center justify-center rounded-sm focus:ring-2 focus:ring-offset-1 focus:outline-none"
                >
                  <XIcon className="h-4 w-4" />
                </div>
                <Separator
                  orientation="vertical"
                  className="flex h-full min-h-6"
                />
                <ChevronDown
                  className="text-text-neutral-tertiary mx-2 h-4 cursor-pointer"
                  aria-hidden="true"
                />
              </div>
            </div>
          ) : (
            <div className="mx-auto flex w-full items-center justify-between">
              <span className="text-text-neutral-tertiary mx-3 text-sm">
                {placeholder}
              </span>
              <ChevronDown className="text-text-neutral-tertiary mx-2 h-4 cursor-pointer" />
            </div>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        container={portalContainer}
        id={listboxId}
        role="listbox"
        aria-multiselectable="true"
        aria-label="Available options"
        className="border-border-input-primary bg-bg-input-primary text-text-neutral-primary pointer-events-auto z-50 w-[var(--radix-popover-trigger-width)] max-w-[var(--radix-popover-trigger-width)] touch-manipulation rounded-lg p-0"
        align="start"
        onEscapeKeyDown={() => setOpen(false)}
      >
        <Command>
          {searchable && (
            <CommandInput
              placeholder="Search options..."
              value={search}
              onValueChange={setSearch}
              aria-label="Search through available options"
            />
          )}
          <CommandList className="minimal-scrollbar multiselect-scrollbar max-h-[40vh] overflow-x-hidden overflow-y-auto overscroll-y-contain">
            <CommandEmpty>{emptyIndicator || "No results found."}</CommandEmpty>
            {!hideSelectAll && !search && (
              <CommandGroup>
                <CommandItem
                  key="all"
                  onSelect={toggleAll}
                  role="option"
                  aria-selected={
                    selectedValues.length === enabledOptions.length
                  }
                  className="cursor-pointer"
                >
                  <Checkbox
                    checked={selectedValues.length === enabledOptions.length}
                    tabIndex={-1}
                    aria-hidden="true"
                    className="pointer-events-none mr-2 size-4"
                  />
                  <span>Select All</span>
                </CommandItem>
              </CommandGroup>
            )}
            <CommandGroup>
              {filteredOptions.map((option) => {
                const isSelected = selectedValues.includes(option.value);
                return (
                  <CommandItem
                    key={option.value}
                    onSelect={() => toggleOption(option.value)}
                    role="option"
                    aria-selected={isSelected}
                    aria-disabled={option.disabled}
                    className={cn(
                      "cursor-pointer",
                      option.disabled && "cursor-not-allowed opacity-50",
                    )}
                    disabled={option.disabled}
                  >
                    <Checkbox
                      checked={isSelected}
                      disabled={option.disabled}
                      tabIndex={-1}
                      aria-hidden="true"
                      className="pointer-events-none mr-2 size-4"
                    />
                    {option.icon && (
                      <span className="shrink-0">{option.icon}</span>
                    )}
                    <div className="flex min-w-0 flex-col">
                      <span className="truncate">{option.label}</span>
                      {option.description && (
                        <span className="text-text-neutral-tertiary text-xs">
                          {option.description}
                        </span>
                      )}
                    </div>
                  </CommandItem>
                );
              })}
            </CommandGroup>
          </CommandList>
          <Separator />
          <div className="flex items-center justify-between p-1">
            {selectedValues.length > 0 && (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleClear}
                  className="flex-1"
                >
                  Clear
                </Button>
                <Separator
                  orientation="vertical"
                  className="flex h-full min-h-6"
                />
              </>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setOpen(false)}
              className="flex-1"
            >
              Close
            </Button>
          </div>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

EnhancedMultiSelect.displayName = "EnhancedMultiSelect";
export type { EnhancedMultiSelectProps, MultiSelectOption };
