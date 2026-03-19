import { CircleAlert } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn";

interface QueryExecutionErrorProps {
  error: string;
}

export const QueryExecutionError = ({ error }: QueryExecutionErrorProps) => {
  return (
    <Alert variant="error">
      <CircleAlert className="size-4" />
      <AlertTitle>Query execution failed</AlertTitle>
      <AlertDescription className="w-full gap-3">
        <p>The Attack Paths query could not be executed.</p>
        <div className="bg-bg-neutral-primary/70 border-border-neutral-secondary w-full rounded-md border px-3 py-2">
          <pre className="text-text-error-primary font-mono text-xs break-words whitespace-pre-wrap">
            {error}
          </pre>
        </div>
      </AlertDescription>
    </Alert>
  );
};
