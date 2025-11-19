"use client";

import { SpinnerIcon } from "@/components/icons";
import { cn } from "@/lib/utils";

interface LoaderProps extends React.HTMLAttributes<HTMLDivElement> {
  /**
   * Size of the loader spinner
   * @default "default"
   */
  size?: "sm" | "default" | "lg";
  /**
   * Optional loading text to display
   */
  text?: string;
  className?: string;
  ref?: React.Ref<HTMLDivElement>;
}

const loaderSizes = {
  sm: 16,
  default: 24,
  lg: 32,
};

const Loader = ({
  size = "default",
  text,
  className,
  ref,
  ...props
}: LoaderProps) => {
  return (
    <div
      ref={ref}
      className={cn("flex items-center gap-2", className)}
      role="status"
      aria-live="polite"
      aria-label={text || "Loading"}
      {...props}
    >
      <SpinnerIcon
        size={loaderSizes[size]}
        className="text-muted-foreground animate-spin"
      />
      {text && <span className="text-muted-foreground text-sm">{text}</span>}
      <span className="sr-only">{text || "Loading..."}</span>
    </div>
  );
};

export { Loader };
