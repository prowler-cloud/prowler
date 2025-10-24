"use client";

import * as SelectPrimitive from "@radix-ui/react-select";
import { CheckIcon, ChevronDownIcon, ChevronUpIcon, X } from "lucide-react";
import { createContext, useContext } from "react";

import { cn } from "@/lib/utils";

// Context for managing multi-select state
type SelectContextValue = {
  multiple?: boolean;
  selectedValues?: string[];
  onMultiValueChange?: (values: string[]) => void;
};

const SelectContext = createContext<SelectContextValue>({});

function Select({
  allowDeselect = false,
  multiple = false,
  value,
  onValueChange,
  selectedValues = [],
  onMultiValueChange,
  ...props
}: Omit<React.ComponentProps<typeof SelectPrimitive.Root>, "onValueChange"> & {
  allowDeselect?: boolean;
  multiple?: boolean;
  selectedValues?: string[];
  onValueChange?: (value: string) => void;
  onMultiValueChange?: (values: string[]) => void;
}) {
  const handleValueChange = (nextValue: string) => {
    if (multiple && onMultiValueChange) {
      // Multi-select: toggle the value
      const newValues = selectedValues.includes(nextValue)
        ? selectedValues.filter((v) => v !== nextValue)
        : [...selectedValues, nextValue];
      onMultiValueChange(newValues);
    } else if (
      allowDeselect &&
      typeof value === "string" &&
      value === nextValue
    ) {
      // Single-select with deselect
      onValueChange?.("");
    } else {
      // Single-select
      onValueChange?.(nextValue);
    }
  };

  const contextValue = {
    multiple,
    selectedValues,
    onMultiValueChange,
  };

  return (
    <SelectContext.Provider value={contextValue}>
      <SelectPrimitive.Root
        data-slot="select"
        value={multiple ? "" : value}
        onValueChange={handleValueChange}
        {...props}
      />
    </SelectContext.Provider>
  );
}

function SelectGroup({
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Group>) {
  return <SelectPrimitive.Group data-slot="select-group" {...props} />;
}

function SelectValue({
  placeholder,
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Value>) {
  const { multiple, selectedValues } = useContext(SelectContext);

  // For multi-select, render custom children or placeholder
  if (multiple) {
    return (
      <span data-slot="select-value">
        {selectedValues && selectedValues.length > 0 ? children : placeholder}
      </span>
    );
  }

  // For single-select, use default Radix behavior
  return (
    <SelectPrimitive.Value
      data-slot="select-value"
      placeholder={placeholder}
      {...props}
    >
      {children}
    </SelectPrimitive.Value>
  );
}

function SelectTrigger({
  className,
  size = "default",
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Trigger> & {
  size?: "sm" | "default";
}) {
  const { multiple, selectedValues, onMultiValueChange } =
    useContext(SelectContext);
  const hasSelection = multiple && selectedValues && selectedValues.length > 0;

  const handleClear = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onMultiValueChange) {
      onMultiValueChange([]);
    }
  };

  return (
    <SelectPrimitive.Trigger
      data-slot="select-trigger"
      data-size={size}
      className={cn(
        "border-input data-[placeholder]:text-muted-foreground [&_svg:not([class*='text-'])]:text-muted-foreground aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:bg-input/30 dark:hover:bg-input/50 flex w-full items-center justify-between gap-2 rounded-lg border border-slate-400 px-4 py-3 text-base leading-7 whitespace-nowrap text-slate-950 shadow-xs transition-[color,box-shadow] outline-none focus-visible:border-slate-600 disabled:cursor-not-allowed disabled:opacity-50 data-[size=default]:h-[52px] data-[size=sm]:h-10 *:data-[slot=select-value]:line-clamp-1 *:data-[slot=select-value]:flex *:data-[slot=select-value]:items-center *:data-[slot=select-value]:gap-2 dark:border-[#262626] dark:bg-[#171717] dark:text-white [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-6",
        className,
      )}
      {...props}
    >
      {children}
      <div className="flex items-center gap-1">
        {hasSelection && (
          <span
            role="button"
            tabIndex={0}
            onClick={handleClear}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                handleClear(e as unknown as React.MouseEvent);
              }
            }}
            className="pointer-events-auto cursor-pointer rounded-sm opacity-70 transition-opacity hover:opacity-100 focus:ring-2 focus:ring-slate-400 focus:ring-offset-2 focus:outline-none"
            aria-label="Clear selection"
          >
            <X className="size-4 text-slate-950 dark:text-white" />
          </span>
        )}
        <SelectPrimitive.Icon asChild>
          <ChevronDownIcon className="size-6 text-slate-950 dark:text-white" />
        </SelectPrimitive.Icon>
      </div>
    </SelectPrimitive.Trigger>
  );
}

function SelectContent({
  className,
  children,
  position = "popper",
  align = "center",
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Content>) {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        data-slot="select-content"
        className={cn(
          "bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 relative z-50 max-h-(--radix-select-content-available-height) min-w-[8rem] origin-(--radix-select-content-transform-origin) overflow-x-hidden overflow-y-auto rounded-lg border border-slate-400 bg-white text-slate-950 shadow-md dark:border-[#262626] dark:bg-[#171717] dark:text-white",
          position === "popper" &&
            "data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1",
          className,
        )}
        position={position}
        align={align}
        {...props}
      >
        <SelectScrollUpButton />
        <SelectPrimitive.Viewport
          className={cn(
            "p-3",
            position === "popper" &&
              "h-[var(--radix-select-trigger-height)] w-full min-w-[var(--radix-select-trigger-width)] scroll-my-1",
          )}
        >
          {children}
        </SelectPrimitive.Viewport>
        <SelectScrollDownButton />
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}

function SelectLabel({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Label>) {
  return (
    <SelectPrimitive.Label
      data-slot="select-label"
      className={cn("text-muted-foreground px-2 py-1.5 text-xs", className)}
      {...props}
    />
  );
}

function SelectItem({
  className,
  children,
  value,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Item>) {
  const { multiple, selectedValues } = useContext(SelectContext);
  const isSelected = multiple && selectedValues?.includes(value);

  return (
    <SelectPrimitive.Item
      data-slot="select-item"
      value={value}
      className={cn(
        "focus:bg-accent focus:text-accent-foreground [&_svg:not([class*='text-'])]:text-muted-foreground relative flex w-full cursor-pointer items-center gap-2 rounded-lg py-2.5 pr-10 pl-3 text-base outline-hidden select-none hover:bg-slate-200 data-[disabled]:pointer-events-none data-[disabled]:opacity-50 dark:hover:bg-slate-700/50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-5",
        className,
      )}
      {...props}
    >
      <SelectPrimitive.ItemText asChild>
        <span className="flex min-w-0 items-center gap-2">{children}</span>
      </SelectPrimitive.ItemText>
      <span className="absolute right-3 flex size-4 items-center justify-center">
        {multiple ? (
          // Multi-select: show check when selected
          isSelected && (
            <CheckIcon className="size-5 text-slate-950 dark:text-white" />
          )
        ) : (
          // Single-select: use radix indicator
          <SelectPrimitive.ItemIndicator>
            <CheckIcon className="size-5 text-slate-950 dark:text-white" />
          </SelectPrimitive.ItemIndicator>
        )}
      </span>
    </SelectPrimitive.Item>
  );
}

function SelectSeparator({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Separator>) {
  return (
    <SelectPrimitive.Separator
      data-slot="select-separator"
      className={cn("bg-border pointer-events-none -mx-1 my-1 h-px", className)}
      {...props}
    />
  );
}

function SelectScrollUpButton({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.ScrollUpButton>) {
  return (
    <SelectPrimitive.ScrollUpButton
      data-slot="select-scroll-up-button"
      className={cn(
        "flex cursor-default items-center justify-center py-1",
        className,
      )}
      {...props}
    >
      <ChevronUpIcon className="size-4 text-slate-950 dark:text-white" />
    </SelectPrimitive.ScrollUpButton>
  );
}

function SelectScrollDownButton({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.ScrollDownButton>) {
  return (
    <SelectPrimitive.ScrollDownButton
      data-slot="select-scroll-down-button"
      className={cn(
        "flex cursor-default items-center justify-center py-1",
        className,
      )}
      {...props}
    >
      <ChevronDownIcon className="size-4 text-slate-950 dark:text-white" />
    </SelectPrimitive.ScrollDownButton>
  );
}

export {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectScrollDownButton,
  SelectScrollUpButton,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
};
