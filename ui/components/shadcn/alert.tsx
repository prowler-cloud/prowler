import { cva, type VariantProps } from "class-variance-authority";
import { X } from "lucide-react";

import { cn } from "@/lib/utils";

const alertVariants = cva(
  "relative w-full rounded-lg border px-4 py-3 text-sm grid has-[>svg]:grid-cols-[calc(var(--spacing)*4)_1fr] grid-cols-[0_1fr] has-[>svg]:gap-x-3 gap-y-0.5 items-start [&>svg]:size-4 [&>svg]:translate-y-0.5 [&>svg]:text-current",
  {
    variants: {
      variant: {
        default: "bg-card text-card-foreground",
        destructive:
          "text-destructive bg-card [&>svg]:text-current *:data-[slot=alert-description]:text-destructive/90",
        error:
          "border-border-error bg-red-50 text-text-error-primary dark:bg-red-950/50 [&>svg]:text-current *:data-[slot=alert-description]:text-red-700 dark:*:data-[slot=alert-description]:text-red-300",
        warning:
          "border-orange-500 bg-orange-50 text-text-warning-primary dark:bg-orange-950/50 [&>svg]:text-current *:data-[slot=alert-description]:text-orange-700 dark:*:data-[slot=alert-description]:text-orange-300",
        info: "border-bg-data-info bg-blue-50 text-bg-data-info dark:bg-blue-950/50 [&>svg]:text-current *:data-[slot=alert-description]:text-blue-700 dark:*:data-[slot=alert-description]:text-blue-300",
        success:
          "border-text-success bg-green-50 text-text-success-primary dark:bg-green-950/50 [&>svg]:text-current *:data-[slot=alert-description]:text-green-700 dark:*:data-[slot=alert-description]:text-green-300",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

interface AlertProps
  extends React.ComponentProps<"div">,
    VariantProps<typeof alertVariants> {
  onClose?: () => void;
}

function Alert({
  className,
  variant,
  onClose,
  children,
  ...props
}: AlertProps) {
  return (
    <div
      data-slot="alert"
      role="alert"
      className={cn(alertVariants({ variant }), className)}
      {...props}
    >
      {children}
      {onClose && (
        <button
          onClick={onClose}
          className="absolute top-3 right-3 rounded-sm opacity-70 transition-opacity hover:opacity-100"
          aria-label="Close"
        >
          <X className="size-4" />
        </button>
      )}
    </div>
  );
}

function AlertTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-title"
      className={cn(
        "col-start-2 line-clamp-1 min-h-4 font-medium tracking-tight",
        className,
      )}
      {...props}
    />
  );
}

function AlertDescription({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-description"
      className={cn(
        "text-muted-foreground col-start-2 grid justify-items-start gap-1 text-sm [&_p]:leading-relaxed",
        className,
      )}
      {...props}
    />
  );
}

export { Alert, AlertDescription, AlertTitle };
