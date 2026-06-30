import { StatusAlert } from "@/components/shared/status-alert";

interface QueryExecutionErrorProps {
  error: string;
  title?: string;
  description?: string;
}

export const QueryExecutionError = ({
  error,
  title = "Query execution failed",
  description,
}: QueryExecutionErrorProps) => {
  return (
    <StatusAlert
      variant="error"
      title={title}
      descriptionClassName="w-full gap-3"
    >
      {description ? <p>{description}</p> : null}
      <div className="bg-bg-neutral-primary/70 border-border-neutral-secondary w-full rounded-md border px-3 py-2">
        <pre className="text-text-error-primary font-mono text-xs break-words whitespace-pre-wrap">
          {error}
        </pre>
      </div>
    </StatusAlert>
  );
};
