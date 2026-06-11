"use client";

import * as SelectPrimitive from "@radix-ui/react-select";
import { CheckIcon, ChevronDownIcon, ChevronUpIcon } from "lucide-react";
import {
  ComponentProps,
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  type WheelEvent,
} from "react";

import { cn } from "@/lib/utils";

const SELECT_CLOSE_ANIMATION_MS = 100;

interface SelectMotionContextValue {
  isClosing: boolean;
}

const SelectMotionContext = createContext<SelectMotionContextValue>({
  isClosing: false,
});

const stopWheelPropagation = (event: WheelEvent<HTMLElement>) => {
  event.stopPropagation();
};

function Select({
  allowDeselect = false,
  open,
  defaultOpen,
  onOpenChange,
  ...props
}: ComponentProps<typeof SelectPrimitive.Root> & {
  allowDeselect?: boolean;
}) {
  const isControlled = open !== undefined;
  const [uncontrolledOpen, setUncontrolledOpen] = useState(
    defaultOpen ?? false,
  );
  const requestedOpen = isControlled ? open : uncontrolledOpen;
  const [renderedOpen, setRenderedOpen] = useState(requestedOpen);
  const [isClosing, setIsClosing] = useState(false);
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (closeTimerRef.current) {
      clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }

    if (requestedOpen) {
      setIsClosing(false);
      setRenderedOpen(true);
      return;
    }

    if (!renderedOpen) {
      setIsClosing(false);
      return;
    }

    setIsClosing(true);
    closeTimerRef.current = setTimeout(() => {
      setRenderedOpen(false);
      setIsClosing(false);
      closeTimerRef.current = null;
    }, SELECT_CLOSE_ANIMATION_MS);

    return () => {
      if (closeTimerRef.current) {
        clearTimeout(closeTimerRef.current);
        closeTimerRef.current = null;
      }
    };
  }, [requestedOpen, renderedOpen]);

  const handleOpenChange = (nextOpen: boolean) => {
    if (!isControlled) {
      setUncontrolledOpen(nextOpen);
    }

    onOpenChange?.(nextOpen);
  };

  const handleValueChange = (nextValue: string) => {
    if (allowDeselect && props.value === nextValue) {
      // Single-select with deselect
      props.onValueChange?.("");
    } else {
      // Single-select
      props.onValueChange?.(nextValue);
    }
  };

  return (
    <SelectMotionContext.Provider value={{ isClosing }}>
      <SelectPrimitive.Root
        data-slot="select"
        {...props}
        open={renderedOpen}
        onOpenChange={handleOpenChange}
        onValueChange={handleValueChange}
      />
    </SelectMotionContext.Provider>
  );
}

function SelectGroup({
  ...props
}: ComponentProps<typeof SelectPrimitive.Group>) {
  return <SelectPrimitive.Group data-slot="select-group" {...props} />;
}

function SelectValue({
  ...props
}: ComponentProps<typeof SelectPrimitive.Value>) {
  return <SelectPrimitive.Value data-slot="select-value" {...props} />;
}

function SelectTrigger({
  className,
  size = "default",
  iconSize = "default",
  children,
  ...props
}: ComponentProps<typeof SelectPrimitive.Trigger> & {
  size?: "sm" | "default";
  iconSize?: "sm" | "default";
}) {
  const { isClosing } = useContext(SelectMotionContext);

  return (
    <SelectPrimitive.Trigger
      data-slot="select-trigger"
      data-size={size}
      data-closing={isClosing ? "true" : undefined}
      className={cn(
        "group border-border-input-primary bg-bg-input-primary text-bg-button-secondary data-[placeholder]:text-bg-button-secondary [&_svg:not([class*='text-'])]:text-bg-button-secondary aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive hover:bg-bg-neutral-tertiary active:bg-border-neutral-tertiary dark:bg-input/30 dark:hover:bg-input/50 focus-visible:border-border-input-primary-press focus-visible:ring-border-input-primary-press flex w-full items-center justify-between gap-2 overflow-hidden rounded-lg border px-4 py-3 text-sm whitespace-nowrap shadow-xs transition-[background-color,border-color,color,box-shadow] duration-150 ease-out outline-none focus-visible:ring-1 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50 has-[>svg]:px-3 data-[size=default]:h-[52px] data-[size=sm]:h-10 *:data-[slot=select-value]:line-clamp-1 *:data-[slot=select-value]:flex *:data-[slot=select-value]:items-center *:data-[slot=select-value]:gap-2 motion-reduce:transition-none dark:focus-visible:ring-slate-400 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-6",
        className,
      )}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon asChild>
        <ChevronDownIcon
          className={cn(
            "text-bg-button-secondary shrink-0 opacity-70 transition-[rotate] duration-200 ease-out motion-reduce:rotate-0 motion-reduce:transition-none",
            isClosing ? "rotate-0" : "group-data-[state=open]:rotate-180",
            iconSize === "sm" ? "size-4" : "size-6",
          )}
          aria-hidden="true"
        />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  );
}

function SelectContent({
  className,
  children,
  position = "popper",
  align = "start",
  width = "default",
  style,
  ...props
}: ComponentProps<typeof SelectPrimitive.Content> & {
  width?: "default" | "wide";
}) {
  const { isClosing } = useContext(SelectMotionContext);
  const widthClasses =
    width === "wide"
      ? "w-[min(max(var(--radix-select-trigger-width),24rem),calc(100vw-2rem))] max-w-[32rem]"
      : undefined;

  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        data-slot="select-content"
        data-closing={isClosing ? "true" : undefined}
        className={cn(
          "bg-popover text-popover-foreground data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 border-border-input-primary bg-bg-input-primary relative z-50 max-h-(--radix-select-content-available-height) min-w-[8rem] origin-(--radix-select-content-transform-origin) overflow-hidden rounded-lg border duration-200 ease-out data-[state=closed]:duration-100 data-[state=closed]:ease-in motion-reduce:transform-none motion-reduce:animate-none motion-reduce:transition-none",
          isClosing
            ? "animate-out fade-out-0 zoom-out-95 pointer-events-none duration-100 ease-in"
            : "data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95",
          position === "popper" &&
            "data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1",
          widthClasses,
          className,
        )}
        style={{
          maxHeight: "var(--radix-select-content-available-height)",
          ...style,
        }}
        position={position}
        align={align}
        {...props}
      >
        <SelectScrollUpButton />
        <SelectPrimitive.Viewport
          data-slot="select-viewport"
          onWheelCapture={stopWheelPropagation}
          style={{
            maxHeight:
              "min(300px, var(--radix-select-content-available-height, 300px))",
          }}
          className={cn(
            "minimal-scrollbar flex flex-col gap-1 overflow-x-hidden overflow-y-auto overscroll-contain p-3",
            position === "popper" &&
              (width === "wide"
                ? "w-full scroll-my-1"
                : "w-full min-w-[var(--radix-select-trigger-width)] scroll-my-1"),
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
  ...props
}: ComponentProps<typeof SelectPrimitive.Item>) {
  return (
    <SelectPrimitive.Item
      data-slot="select-item"
      className={cn(
        "focus:bg-accent focus:text-accent-foreground [&_svg:not([class*='text-'])]:text-bg-button-secondary text-bg-button-secondary relative flex w-full cursor-pointer items-center gap-2 rounded-lg py-3 pr-12 pl-4 text-sm outline-hidden transition-colors duration-150 ease-out select-none hover:bg-slate-200 data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50 motion-reduce:transition-none dark:hover:bg-slate-700/50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-5",
        className,
      )}
      {...props}
    >
      <SelectPrimitive.ItemText asChild>
        <span className="flex min-w-0 flex-1 items-center gap-2">
          {children}
        </span>
      </SelectPrimitive.ItemText>
      <SelectPrimitive.ItemIndicator asChild>
        <CheckIcon className="text-bg-button-secondary animate-in fade-in-0 zoom-in-75 absolute right-4 size-5 duration-150 ease-out motion-reduce:animate-none" />
      </SelectPrimitive.ItemIndicator>
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
