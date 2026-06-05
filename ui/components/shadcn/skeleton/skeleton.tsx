import { cn } from "@/lib/utils";

function Skeleton({
  className,
  children,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn(
        "bg-border-neutral-tertiary relative overflow-hidden rounded-md transition-colors duration-500 ease-out motion-reduce:transition-none",
        className,
      )}
      {...props}
    >
      <span
        data-slot="skeleton-scanner"
        className="animate-skeleton-scan pointer-events-none absolute inset-y-0 -left-1/2 w-1/2 bg-gradient-to-r from-transparent via-white/10 to-transparent motion-reduce:hidden"
      />
      {children}
    </div>
  );
}

export { Skeleton };
