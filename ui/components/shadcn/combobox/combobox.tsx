"use client";

import { cva, type VariantProps } from "class-variance-authority";
import { Check, ChevronsUpDown, Loader2 } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
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
import { cn } from "@/lib/utils";

const comboboxTriggerVariants = cva("", {
  variants: {
    variant: {
      default:
        "w-full justify-between rounded-xl border border-border-neutral-secondary bg-bg-neutral-secondary hover:bg-bg-neutral-tertiary",
      ghost:
        "border-none bg-transparent shadow-none hover:bg-accent hover:text-foreground",
    },
  },
  defaultVariants: {
    variant: "default",
  },
});

const comboboxContentVariants = cva("p-0", {
  variants: {
    variant: {
      default:
        "w-[calc(100vw-2rem)] max-w-md rounded-xl border border-border-neutral-secondary bg-bg-neutral-secondary shadow-md sm:w-full",
      ghost:
        "w-[calc(100vw-2rem)] max-w-md rounded-lg border border-slate-400 bg-white sm:w-full dark:border-[#262626] dark:bg-[#171717]",
    },
  },
  defaultVariants: {
    variant: "default",
  },
});

export interface ComboboxOption {
  value: string;
  label: string;
}

export interface ComboboxGroup {
  heading: string;
  options: ComboboxOption[];
}

export interface ComboboxProps
  extends VariantProps<typeof comboboxTriggerVariants> {
  value?: string;
  onValueChange?: (value: string) => void;
  options?: ComboboxOption[];
  groups?: ComboboxGroup[];
  placeholder?: string;
  searchPlaceholder?: string;
  emptyMessage?: string;
  className?: string;
  triggerClassName?: string;
  contentClassName?: string;
  disabled?: boolean;
  showSelectedFirst?: boolean;
  loading?: boolean;
  loadingMessage?: string;
}

export function Combobox({
  value,
  onValueChange,
  options = [],
  groups = [],
  placeholder = "Select option...",
  searchPlaceholder = "Search...",
  emptyMessage = "No option found.",
  className,
  triggerClassName,
  contentClassName,
  variant = "default",
  disabled = false,
  showSelectedFirst = true,
  loading = false,
  loadingMessage = "Loading...",
}: ComboboxProps) {
  const [open, setOpen] = useState(false);

  const selectedOption =
    options.find((option) => option.value === value) ||
    groups
      .flatMap((group) => group.options)
      .find((option) => option.value === value);

  const handleSelect = (selectedValue: string) => {
    onValueChange?.(selectedValue === value ? "" : selectedValue);
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          disabled={disabled}
          className={cn(
            comboboxTriggerVariants({ variant }),
            triggerClassName,
            className,
          )}
        >
          <span className="truncate">
            {selectedOption ? selectedOption.label : placeholder}
          </span>
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className={cn(comboboxContentVariants({ variant }), contentClassName)}
        align="start"
      >
        <Command>
          {!loading && (
            <CommandInput placeholder={searchPlaceholder} className="h-9" />
          )}
          <CommandList className="minimal-scrollbar max-h-[400px]">
            {loading && (
              <div className="text-text-neutral-tertiary flex items-center gap-2 px-3 py-2 text-sm">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>{loadingMessage}</span>
              </div>
            )}
            <CommandEmpty>{emptyMessage}</CommandEmpty>

            {/* Show selected option first if enabled */}
            {showSelectedFirst && selectedOption && (
              <CommandGroup heading="Current Selection">
                <CommandItem
                  value={selectedOption.value}
                  onSelect={handleSelect}
                >
                  <Check className="mr-2 h-4 w-4 opacity-100" />
                  {selectedOption.label}
                </CommandItem>
              </CommandGroup>
            )}

            {/* Render grouped options */}
            {groups.length > 0 &&
              groups.map((group) => {
                const availableOptions = showSelectedFirst
                  ? group.options.filter((option) => option.value !== value)
                  : group.options;

                if (availableOptions.length === 0) return null;

                return (
                  <CommandGroup key={group.heading} heading={group.heading}>
                    {availableOptions.map((option) => (
                      <CommandItem
                        key={option.value}
                        value={option.value}
                        onSelect={handleSelect}
                      >
                        <Check
                          className={cn(
                            "mr-2 h-4 w-4",
                            value === option.value
                              ? "opacity-100"
                              : "opacity-0",
                          )}
                        />
                        {option.label}
                      </CommandItem>
                    ))}
                  </CommandGroup>
                );
              })}

            {/* Render flat options if no groups */}
            {groups.length === 0 && options.length > 0 && (
              <CommandGroup>
                {options
                  .filter(
                    (option) => !showSelectedFirst || option.value !== value,
                  )
                  .map((option) => (
                    <CommandItem
                      key={option.value}
                      value={option.value}
                      onSelect={handleSelect}
                    >
                      <Check
                        className={cn(
                          "mr-2 h-4 w-4",
                          value === option.value ? "opacity-100" : "opacity-0",
                        )}
                      />
                      {option.label}
                    </CommandItem>
                  ))}
              </CommandGroup>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
