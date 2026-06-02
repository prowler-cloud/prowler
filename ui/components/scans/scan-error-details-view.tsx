"use client";

import type { ScanErrorDetails } from "@/actions/task/task.adapter";
import { Field, FieldLabel, LabeledField } from "@/components/shadcn";
import { CodeSnippet } from "@/components/ui/code-snippet/code-snippet";

interface ScanErrorDetailsViewProps {
  details: ScanErrorDetails;
  copyAriaLabel?: string;
}

export function ScanErrorDetailsView({
  details,
  copyAriaLabel = "Copy error details",
}: ScanErrorDetailsViewProps) {
  return (
    <div className="flex flex-col gap-8">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <LabeledField label="Error Type">{details.type}</LabeledField>
        {details.module && (
          <LabeledField label="Module">{details.module}</LabeledField>
        )}
      </div>
      <Field>
        <FieldLabel>Error</FieldLabel>
        <CodeSnippet
          value={details.copyValue}
          formatter={() => details.messages.join("\n")}
          multiline
          ariaLabel={copyAriaLabel}
        />
      </Field>
    </div>
  );
}
