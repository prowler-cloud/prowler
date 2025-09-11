import { AlertIcon } from "@/components/icons/Icons";
import { cn } from "@/lib/utils";

type FeedbackType = "error" | "warning" | "info" | "success";

interface FeedbackBannerProps {
  type?: FeedbackType;
  title: string;
  message: string;
  className?: string;
}

const typeStyles: Record<
  FeedbackType,
  { border: string; bg: string; text: string }
> = {
  error: {
    border: "border-danger",
    bg: "bg-system-error-light/30 dark:bg-system-error-light/80",
    text: "text-danger",
  },
  warning: {
    border: "border-warning",
    bg: "bg-yellow-100 dark:bg-yellow-200",
    text: "text-yellow-800",
  },
  info: {
    border: "border-blue-400",
    bg: "bg-blue-50 dark:bg-blue-100",
    text: "text-blue-800",
  },
  success: {
    border: "border-green-500",
    bg: "bg-green-50 dark:bg-green-100",
    text: "text-green-800",
  },
};

export const FeedbackBanner: React.FC<FeedbackBannerProps> = ({
  type = "info",
  title,
  message,
  className,
}) => {
  const styles = typeStyles[type];

  return (
    <div
      className={cn(
        "rounded-xl border-l-4 p-4 shadow-sm",
        styles.border,
        styles.bg,
        className,
      )}
    >
      <div className="flex items-center gap-3">
        <span className={cn("mt-1", styles.text)}>
          <AlertIcon size={20} />
        </span>
        <p className={cn("text-sm", styles.text)}>
          <strong>{title}</strong> {message}
        </p>
      </div>
    </div>
  );
};
