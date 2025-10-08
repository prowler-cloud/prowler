interface WarningAlertProps {
  title?: string;
  message: string;
  variant?: "warning" | "danger";
}

export const WarningAlert = ({
  title = "Warning",
  message,
  variant = "warning",
}: WarningAlertProps) => {
  const colorClasses =
    variant === "danger"
      ? "bg-danger-50 text-danger-700"
      : "bg-warning-50 text-warning-700";

  return (
    <div className={`${colorClasses} rounded-lg p-4 text-sm`}>
      <div className="flex items-start gap-2">
        <div className="mt-0.5">⚠️</div>
        <div>
          <strong>{title}:</strong> {message}
        </div>
      </div>
    </div>
  );
};
