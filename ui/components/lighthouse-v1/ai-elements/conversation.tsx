"use client";

import { ArrowDownIcon } from "lucide-react";
import type { ComponentProps, ReactNode } from "react";
import { StickToBottom, useStickToBottomContext } from "use-stick-to-bottom";

import { Button } from "@/components/shadcn/button/button";
import { cn } from "@/lib/utils";

export type ConversationProps = ComponentProps<typeof StickToBottom>;

export const Conversation = ({ className, ...props }: ConversationProps) => (
  <StickToBottom
    className={cn("relative flex-1 overflow-y-hidden", className)}
    initial="smooth"
    resize="smooth"
    role="log"
    {...props}
  />
);

type ConversationContentChildren =
  | ReactNode
  | ((context: ReturnType<typeof useStickToBottomContext>) => ReactNode);

export type ConversationContentProps = Omit<
  ComponentProps<"div">,
  "children" | "ref"
> & {
  children?: ConversationContentChildren;
  scrollClassName?: string;
};

export const ConversationContent = ({
  children,
  className,
  scrollClassName,
  ...props
}: ConversationContentProps) => {
  const context = useStickToBottomContext();
  const { contentRef, scrollRef } = context;

  return (
    <div
      ref={scrollRef}
      className={cn("h-full min-h-0 w-full overflow-y-auto", scrollClassName)}
    >
      <div
        ref={contentRef}
        className={cn("flex flex-col gap-8 p-4", className)}
        {...props}
      >
        {typeof children === "function" ? children(context) : children}
      </div>
    </div>
  );
};

export type ConversationEmptyStateProps = ComponentProps<"div"> & {
  title?: string;
  description?: string;
  icon?: ReactNode;
};

export const ConversationEmptyState = ({
  className,
  title = "No messages yet",
  description = "Start a conversation to see messages here",
  icon,
  children,
  ...props
}: ConversationEmptyStateProps) => (
  <div
    className={cn(
      "flex size-full flex-col items-center justify-center gap-3 p-8 text-center",
      className,
    )}
    {...props}
  >
    {children ?? (
      <>
        {icon && <div className="text-muted-foreground">{icon}</div>}
        <div className="space-y-1">
          <h3 className="text-sm font-medium">{title}</h3>
          {description && (
            <p className="text-muted-foreground text-sm">{description}</p>
          )}
        </div>
      </>
    )}
  </div>
);

export type ConversationScrollButtonProps = ComponentProps<typeof Button>;

export const ConversationScrollButton = ({
  className,
  ...props
}: ConversationScrollButtonProps) => {
  const { isAtBottom, scrollToBottom } = useStickToBottomContext();

  const handleScrollToBottom = () => {
    scrollToBottom();
  };

  return (
    !isAtBottom && (
      <Button
        aria-label="Scroll to bottom"
        className={cn(
          "absolute bottom-4 left-[50%] translate-x-[-50%] rounded-full",
          className,
        )}
        onClick={handleScrollToBottom}
        size="icon"
        type="button"
        variant="outline"
        {...props}
      >
        <ArrowDownIcon className="size-4" />
      </Button>
    )
  );
};
