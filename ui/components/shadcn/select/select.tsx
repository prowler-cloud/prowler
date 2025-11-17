"use client";

import * as SelectPrimitive from "@radix-ui/react-select";
import { CheckIcon, ChevronDownIcon, ChevronUpIcon, X } from "lucide-react";
import {
  ComponentProps,
  createContext,
  KeyboardEvent,
  MouseEvent,
  useContext,
  useId,
} from "react";

import { cn } from "@/lib/utils";

// Context for managing multi-select state
type SelectContextValue = {
  multiple?: boolean;
  selectedValues?: string[];
  onMultiValueChange?: (values: string[]) => void;
  ariaLabel?: string;
  liveRegionId?: string;
};

const SelectContext = createContext<SelectContextValue>({});

function Select({
  allowDeselect = false,
  multiple = false,
  value,
  onValueChange,
  selectedValues = [],
  onMultiValueChange,
  ariaLabel,
  ...props
}: Omit<ComponentProps<typeof SelectPrimitive.Root>, "onValueChange"> & {
  allowDeselect?: boolean;
  multiple?: boolean;
  selectedValues?: string[];
  onValueChange?: (value: string) => void;
  onMultiValueChange?: (values: string[]) => void;
  ariaLabel?: string;
}) {
  const liveRegionId = useId();

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
    ariaLabel,
    liveRegionId,
  };

  return (
    <SelectContext.Provider value={contextValue}>
      <SelectPrimitive.Root
        data-slot="select"
        value={multiple ? "" : value}
        onValueChange={handleValueChange}
        {...props}
      />
      {/* Live region for screen reader announcements */}
      {multiple && (
        <div
          id={liveRegionId}
          role="status"
          aria-live="polite"
          aria-atomic="true"
          className="sr-only"
        >
          {selectedValues.length > 0
            ? `${selectedValues.length} ${selectedValues.length === 1 ? "item" : "items"} selected`
            : "No items selected"}
        </div>
      )}
    </SelectContext.Provider>
  );
}

function SelectGroup({
  ...props
}: ComponentProps<typeof SelectPrimitive.Group>) {
  return <SelectPrimitive.Group data-slot="select-group" {...props} />;
}

function SelectValue({
  placeholder,
  children,
  ...props
}: ComponentProps<typeof SelectPrimitive.Value>) {
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
}: ComponentProps<typeof SelectPrimitive.Trigger> & {
  size?: "sm" | "default";
}) {
  const { multiple, selectedValues, onMultiValueChange, ariaLabel } =
    useContext(SelectContext);
  const hasSelection = multiple && selectedValues && selectedValues.length > 0;

  const handleClear = (
    e: MouseEvent<HTMLSpanElement> | KeyboardEvent<HTMLSpanElement>,
  ) => {
    e.stopPropagation();
    if (onMultiValueChange) {
      onMultiValueChange([]);
    }
  };

  const clearButtonLabel = `Clear ${ariaLabel || "selection"}${hasSelection ? ` (${selectedValues.length} selected)` : ""}`;

  return (
    <SelectPrimitive.Trigger
      data-slot="select-trigger"
      data-size={size}
      aria-label={ariaLabel}
      aria-multiselectable={multiple ? "true" : undefined}
      className={cn(
        "border-border-input-primary bg-bg-input-primary text-bg-button-secondary data-[placeholder]:text-bg-button-secondary [&_svg:not([class*='text-'])]:text-bg-button-secondary aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:bg-input/30 dark:hover:bg-input/50 focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press flex w-full items-center justify-between gap-2 rounded-lg border px-4 py-3 text-sm whitespace-nowrap shadow-xs transition-[color,box-shadow] outline-none focus-visible:ring-1 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50 data-[size=default]:h-[52px] data-[size=sm]:h-10 *:data-[slot=select-value]:line-clamp-1 *:data-[slot=select-value]:flex *:data-[slot=select-value]:items-center *:data-[slot=select-value]:gap-2 dark:focus-visible:ring-slate-400 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-6",
        className,
      )}
      {...props}
    >
      {children}
      <div className="flex items-center gap-1">
        {hasSelection && (
          <span
            role="button"
            tabIndex={-1}
            onClick={handleClear}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                e.stopPropagation();
                handleClear(e);
              }
            }}
            className="pointer-events-auto cursor-pointer rounded-sm p-0.5 opacity-70 transition-opacity hover:opacity-100 focus:opacity-100 focus:ring-2 focus:ring-slate-600 focus:ring-offset-2 focus:outline-none dark:focus:ring-slate-400"
            aria-label={clearButtonLabel}
          >
            <X className="text-bg-button-secondary size-4" aria-hidden="true" />
          </span>
        )}
        <SelectPrimitive.Icon asChild>
          <ChevronDownIcon
            className="text-bg-button-secondary size-6"
            aria-hidden="true"
          />
        </SelectPrimitive.Icon>
      </div>
    </SelectPrimitive.Trigger>
  );
}

function SelectContent({
  className,
  children,
  position = "popper",
  align = "start",
  ...props
}: ComponentProps<typeof SelectPrimitive.Content>) {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        data-slot="select-content"
        className={cn(
          "bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 border-border-input-primary bg-bg-input-primary relative z-50 max-h-(--radix-select-content-available-height) min-w-[8rem] origin-(--radix-select-content-transform-origin) overflow-x-hidden overflow-y-auto rounded-lg border",
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
            "flex flex-col gap-1 p-3",
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
}: ComponentProps<typeof SelectPrimitive.Label>) {
  return (
    <SelectPrimitive.Label
      data-slot="select-label"
      className={cn("text-bg-button-secondary px-2 py-1.5 text-xs", className)}
      {...props}
    />
  );
}

function SelectItem({
  className,
  children,
  value,
  ...props
}: ComponentProps<typeof SelectPrimitive.Item>) {
  const { multiple, selectedValues } = useContext(SelectContext);
  const isSelected = multiple && selectedValues?.includes(value);

  return (
    <SelectPrimitive.Item
      data-slot="select-item"
      value={value}
      aria-selected={multiple ? isSelected : undefined}
      aria-checked={multiple ? isSelected : undefined}
      role={multiple ? "option" : undefined}
      className={cn(
        "focus:bg-accent focus:text-accent-foreground [&_svg:not([class*='text-'])]:text-bg-button-secondary text-bg-button-secondary relative flex w-full cursor-pointer items-center gap-2 rounded-lg py-2.5 pr-10 pl-3 text-sm outline-hidden select-none hover:bg-slate-200 data-[disabled]:pointer-events-none data-[disabled]:opacity-50 dark:hover:bg-slate-700/50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-5",
        isSelected && "bg-slate-100 dark:bg-slate-800/50",
        className,
      )}
      {...props}
    >
      <SelectPrimitive.ItemText asChild>
        <span className="flex min-w-0 items-center gap-2">{children}</span>
      </SelectPrimitive.ItemText>
      <span
        className="absolute right-3 flex size-4 items-center justify-center"
        aria-hidden="true"
      >
        {multiple ? (
          // Multi-select: show check when selected
          isSelected && (
            <CheckIcon className="text-bg-button-secondary size-5" />
          )
        ) : (
          // Single-select: use radix indicator
          <SelectPrimitive.ItemIndicator>
            <CheckIcon className="text-bg-button-secondary size-5" />
          </SelectPrimitive.ItemIndicator>
        )}
      </span>
    </SelectPrimitive.Item>
  );
}

function SelectSeparator({
  className,
  ...props
}: ComponentProps<typeof SelectPrimitive.Separator>) {
  return (
    <SelectPrimitive.Separator
      data-slot="select-separator"
      className={cn("bg-border pointer-events-none -mx-1 my-1 h-px", className)}
      {...props}
    />
  );
}

function SelectAllItem({
  className,
  children = "Select All",
  allValues = [],
  ...props
}: Omit<ComponentProps<"div">, "children"> & {
  children?: React.ReactNode;
  allValues?: string[];
}) {
  const { multiple, selectedValues, onMultiValueChange } =
    useContext(SelectContext);

  if (!multiple || !onMultiValueChange) {
    return null;
  }

  const allSelected =
    allValues.length > 0 && selectedValues?.length === allValues.length;

  const handleSelectAll = () => {
    if (allSelected) {
      // Deselect all
      onMultiValueChange([]);
    } else {
      // Select all
      onMultiValueChange(allValues);
    }
  };

  return (
    <div
      role="option"
      aria-selected={allSelected}
      data-slot="select-all-item"
      className={cn(
        "focus:bg-accent focus:text-accent-foreground [&_svg:not([class*='text-'])]:text-bg-button-secondary text-bg-button-secondary relative flex w-full cursor-pointer items-center gap-2 rounded-lg py-2.5 pr-10 pl-3 text-sm outline-hidden select-none hover:bg-slate-200 dark:hover:bg-slate-700/50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-5",
        allSelected && "bg-bg-input-primary-fill",
        "font-semibold",
        className,
      )}
      onClick={handleSelectAll}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          handleSelectAll();
        }
      }}
      tabIndex={0}
      {...props}
    >
      <span className="flex min-w-0 items-center gap-1">{children}</span>
      <span
        className="absolute right-2 flex size-4 items-center justify-center"
        aria-hidden="true"
      >
        {allSelected && (
          <CheckIcon className="text-bg-button-secondary size-5" />
        )}
      </span>
    </div>
  );
}

function SelectScrollUpButton({
  className,
  ...props
}: ComponentProps<typeof SelectPrimitive.ScrollUpButton>) {
  return (
    <SelectPrimitive.ScrollUpButton
      data-slot="select-scroll-up-button"
      className={cn(
        "flex cursor-default items-center justify-center py-1",
        className,
      )}
      {...props}
    >
      <ChevronUpIcon className="text-bg-button-secondary size-4" />
    </SelectPrimitive.ScrollUpButton>
  );
}

function SelectScrollDownButton({
  className,
  ...props
}: ComponentProps<typeof SelectPrimitive.ScrollDownButton>) {
  return (
    <SelectPrimitive.ScrollDownButton
      data-slot="select-scroll-down-button"
      className={cn(
        "flex cursor-default items-center justify-center py-1",
        className,
      )}
      {...props}
    >
      <ChevronDownIcon className="text-bg-button-secondary size-4" />
    </SelectPrimitive.ScrollDownButton>
  );
}

export {
  Select,
  SelectAllItem,
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
