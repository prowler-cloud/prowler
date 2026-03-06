"use client";

import { CheckIcon, ChevronDown, XIcon } from "lucide-react";
import {
  type ComponentPropsWithoutRef,
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/shadcn/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
import { cn } from "@/lib/utils";

type MultiSelectContextType = {
  open: boolean;
  setOpen: (open: boolean) => void;
  selectedValues: Set<string>;
  toggleValue: (value: string) => void;
  items: Map<string, ReactNode>;
  onItemAdded: (value: string, label: ReactNode) => void;
  onValuesChange?: (values: string[]) => void;
};
const MultiSelectContext = createContext<MultiSelectContextType | null>(null);

export function MultiSelect({
  children,
  values,
  defaultValues,
  onValuesChange,
}: {
  children: ReactNode;
  values?: string[];
  defaultValues?: string[];
  onValuesChange?: (values: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [internalValues, setInternalValues] = useState(
    new Set<string>(values ?? defaultValues),
  );
  const selectedValues = values ? new Set(values) : internalValues;
  const [items, setItems] = useState<Map<string, ReactNode>>(new Map());

  function toggleValue(value: string) {
    const getNewSet = (prev: Set<string>) => {
      const newSet = new Set(prev);
      if (newSet.has(value)) {
        newSet.delete(value);
      } else {
        newSet.add(value);
      }
      return newSet;
    };
    setInternalValues(getNewSet);
    onValuesChange?.(Array.from(getNewSet(selectedValues)));
  }

  const onItemAdded = useCallback((value: string, label: ReactNode) => {
    setItems((prev) => {
      if (prev.get(value) === label) return prev;
      return new Map(prev).set(value, label);
    });
  }, []);

  return (
    <MultiSelectContext
      value={{
        open,
        setOpen,
        selectedValues,
        toggleValue,
        items,
        onItemAdded,
        onValuesChange,
      }}
    >
      <Popover open={open} onOpenChange={setOpen} modal={true}>
        {children}
      </Popover>
    </MultiSelectContext>
  );
}

export function MultiSelectTrigger({
  className,
  children,
  size = "default",
  ...props
}: {
  className?: string;
  children?: ReactNode;
  size?: "sm" | "default";
} & ComponentPropsWithoutRef<typeof Button>) {
  const { open } = useMultiSelectContext();

  return (
    <PopoverTrigger asChild>
      <Button
        {...props}
        variant={props.variant ?? "outline"}
        role={props.role ?? "combobox"}
        aria-expanded={props["aria-expanded"] ?? open}
        data-slot="multiselect-trigger"
        data-size={size}
        className={cn(
          "border-border-input-primary bg-bg-input-primary text-bg-button-secondary data-[placeholder]:text-bg-button-secondary [&_svg:not([class*='text-'])]:text-bg-button-secondary aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:bg-input/30 dark:hover:bg-input/50 focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press flex w-full items-center justify-between gap-2 rounded-lg border px-4 py-3 text-sm whitespace-nowrap shadow-xs transition-[color,box-shadow] outline-none focus-visible:ring-1 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50 data-[size=default]:h-[52px] data-[size=sm]:h-10 *:data-[slot=multiselect-value]:line-clamp-1 *:data-[slot=multiselect-value]:flex *:data-[slot=multiselect-value]:items-center *:data-[slot=multiselect-value]:gap-2 dark:focus-visible:ring-slate-400 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-6",
          className,
        )}
      >
        {children}
        <ChevronDown
          className={cn(
            "text-bg-button-secondary size-6 shrink-0 opacity-70 transition-transform duration-200",
            open && "rotate-180",
          )}
        />
      </Button>
    </PopoverTrigger>
  );
}

export function MultiSelectValue({
  placeholder,
  clickToRemove = true,
  className,
  overflowBehavior = "wrap-when-open",
  ...props
}: {
  placeholder?: string;
  clickToRemove?: boolean;
  overflowBehavior?: "wrap" | "wrap-when-open" | "cutoff";
} & Omit<ComponentPropsWithoutRef<"div">, "children">) {
  const { selectedValues, toggleValue, items, open } = useMultiSelectContext();
  const [overflowAmount, setOverflowAmount] = useState(0);
  const valueRef = useRef<HTMLDivElement>(null);
  const overflowRef = useRef<HTMLDivElement>(null);

  const shouldWrap =
    overflowBehavior === "wrap" ||
    (overflowBehavior === "wrap-when-open" && open);

  const checkOverflow = useCallback(() => {
    if (valueRef.current === null) return;

    const containerElement = valueRef.current;
    const overflowElement = overflowRef.current;
    const items = containerElement.querySelectorAll<HTMLElement>(
      "[data-selected-item]",
    );

    if (overflowElement !== null) overflowElement.style.display = "none";
    items.forEach((child) => child.style.removeProperty("display"));
    let amount = 0;
    for (let i = items.length - 1; i >= 0; i--) {
      const child = items[i]!;
      if (containerElement.scrollWidth <= containerElement.clientWidth) {
        break;
      }
      amount = items.length - i;
      child.style.display = "none";
      overflowElement?.style.removeProperty("display");
    }
    setOverflowAmount(amount);
  }, []);

  const handleResize = useCallback(
    (node: HTMLDivElement) => {
      valueRef.current = node;

      const mutationObserver = new MutationObserver(checkOverflow);
      const observer = new ResizeObserver(debounce(checkOverflow, 100));

      mutationObserver.observe(node, {
        childList: true,
        attributes: true,
        attributeFilter: ["class", "style"],
      });
      observer.observe(node);

      return () => {
        observer.disconnect();
        mutationObserver.disconnect();
        valueRef.current = null;
      };
    },
    [checkOverflow],
  );

  return (
    <div
      {...props}
      ref={handleResize}
      data-slot="multiselect-value"
      className={cn(
        "flex w-full gap-1.5 overflow-hidden",
        shouldWrap && "h-full flex-wrap",
        className,
      )}
    >
      {placeholder && (
        <span className="text-bg-button-secondary shrink-0 font-normal">
          {placeholder}
        </span>
      )}
      {Array.from(selectedValues)
        .filter((value) => items.has(value))
        .map((value) => (
          <Badge
            variant="tag"
            data-selected-item
            className="group flex items-center gap-1.5 px-2 py-1 text-xs font-medium"
            key={value}
            onClick={
              clickToRemove
                ? (e) => {
                    e.stopPropagation();
                    toggleValue(value);
                  }
                : undefined
            }
          >
            {items.get(value)}
            {clickToRemove && (
              <XIcon className="text-text-neutral-primary group-hover:text-destructive size-3 transition-colors" />
            )}
          </Badge>
        ))}
      <Badge
        style={{
          display: overflowAmount > 0 && !shouldWrap ? "block" : "none",
        }}
        variant="tag"
        ref={overflowRef}
        className="px-2 py-1 text-xs font-medium"
      >
        +{overflowAmount}
      </Badge>
    </div>
  );
}

export function MultiSelectContent({
  search = true,
  children,
  width = "default",
  ...props
}: {
  search?: boolean | { placeholder?: string; emptyMessage?: string };
  children: ReactNode;
  width?: "default" | "wide";
} & Omit<ComponentPropsWithoutRef<typeof Command>, "children">) {
  const canSearch = typeof search === "object" ? true : search;

  const widthClasses =
    width === "wide" ? "w-auto min-w-[400px] max-w-[600px]" : "w-auto";

  return (
    <>
      <div style={{ display: "none" }}>
        <Command>
          <CommandList>{children}</CommandList>
        </Command>
      </div>
      <PopoverContent
        align="start"
        data-slot="multiselect-content"
        className={cn(
          "bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 border-border-input-primary bg-bg-input-primary relative z-50 rounded-lg border p-0",
          widthClasses,
        )}
      >
        <Command {...props} className="rounded-lg">
          {canSearch ? (
            <CommandInput
              placeholder={
                typeof search === "object" ? search.placeholder : undefined
              }
              className="text-bg-button-secondary placeholder:text-bg-button-secondary"
            />
          ) : (
            <button className="sr-only" />
          )}
          <CommandList className="minimal-scrollbar max-h-[300px] overflow-x-hidden overflow-y-auto">
            <div className="flex flex-col gap-1 p-3">
              {canSearch && (
                <CommandEmpty className="text-bg-button-secondary py-6 text-center text-sm">
                  {typeof search === "object" ? search.emptyMessage : undefined}
                </CommandEmpty>
              )}
              {children}
            </div>
          </CommandList>
        </Command>
      </PopoverContent>
    </>
  );
}

export function MultiSelectItem({
  value,
  children,
  badgeLabel,
  onSelect,
  className,
  ...props
}: {
  badgeLabel?: ReactNode;
  value: string;
} & Omit<ComponentPropsWithoutRef<typeof CommandItem>, "value">) {
  const { toggleValue, selectedValues, onItemAdded } = useMultiSelectContext();
  const isSelected = selectedValues.has(value);

  useEffect(() => {
    onItemAdded(value, badgeLabel ?? children);
  }, [value, children, onItemAdded, badgeLabel]);

  return (
    <CommandItem
      {...props}
      value={value}
      data-slot="multiselect-item"
      className={cn(
        "focus:bg-accent focus:text-accent-foreground [&_svg:not([class*='text-'])]:text-bg-button-secondary text-bg-button-secondary flex w-full cursor-pointer items-center justify-between gap-3 rounded-lg px-4 py-3 text-sm outline-hidden select-none hover:bg-slate-200 data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50 dark:hover:bg-slate-700/50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-5",
        isSelected && "bg-slate-100 dark:bg-slate-800/50",
        className,
      )}
      onSelect={() => {
        toggleValue(value);
        onSelect?.(value);
      }}
    >
      <span className="flex min-w-0 flex-1 items-center gap-2">{children}</span>
      <CheckIcon
        className={cn(
          "text-bg-button-secondary size-5 shrink-0",
          isSelected ? "opacity-100" : "opacity-0",
        )}
      />
    </CommandItem>
  );
}

export function MultiSelectGroup(
  props: ComponentPropsWithoutRef<typeof CommandGroup>,
) {
  return <CommandGroup data-slot="multiselect-group" {...props} />;
}

export function MultiSelectSeparator({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof CommandSeparator>) {
  return (
    <CommandSeparator
      data-slot="multiselect-separator"
      className={cn("bg-border pointer-events-none -mx-1 my-1 h-px", className)}
      {...props}
    />
  );
}

export function MultiSelectSelectAll({
  className,
  children = "Select All",
  ...props
}: Omit<ComponentPropsWithoutRef<"button">, "children"> & {
  children?: ReactNode;
}) {
  const { selectedValues, onValuesChange } = useMultiSelectContext();

  if (!onValuesChange) {
    return null;
  }

  const hasSelections = selectedValues.size > 0;

  const handleClearAll = () => {
    // Clear all selections
    onValuesChange?.([]);
  };

  return (
    <button
      type="button"
      data-slot="multiselect-select-all"
      className={cn(
        "focus:bg-accent focus:text-accent-foreground [&_svg:not([class*='text-'])]:text-bg-button-secondary text-bg-button-secondary flex w-full cursor-pointer items-center justify-between gap-3 rounded-lg px-4 py-3 text-sm outline-hidden select-none hover:bg-slate-200 dark:hover:bg-slate-700/50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-5",
        hasSelections && "text-destructive hover:text-destructive",
        "font-semibold",
        className,
      )}
      onClick={handleClearAll}
      {...props}
    >
      <span className="flex min-w-0 flex-1 items-center gap-2">{children}</span>
    </button>
  );
}

function useMultiSelectContext() {
  const context = useContext(MultiSelectContext);
  if (context === null) {
    throw new Error(
      "useMultiSelectContext must be used within a MultiSelectContext",
    );
  }
  return context;
}

function debounce<T extends (...args: never[]) => void>(
  func: T,
  wait: number,
): (...args: Parameters<T>) => void {
  let timeout: ReturnType<typeof setTimeout> | null = null;
  return function (this: unknown, ...args: Parameters<T>) {
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}
