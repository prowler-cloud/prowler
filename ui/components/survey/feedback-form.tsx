"use client";

import { Button } from "@/components/shadcn/button/button";
import { Textarea } from "@/components/shadcn/textarea/textarea";

interface FeedbackFormProps {
  title: string;
  description?: string;
  detailsLabel: string;
  placeholder?: string;
  details: string;
  detailsMaxLength?: number;
  submitLabel?: string;
  isSubmitting?: boolean;
  submitDisabled?: boolean;
  error?: string | null;
  onDetailsChange: (details: string) => void;
  onSubmit: () => void;
  onCancel?: () => void;
}

export function FeedbackForm({
  title,
  description,
  detailsLabel,
  placeholder,
  details,
  detailsMaxLength,
  submitLabel = "Submit",
  isSubmitting = false,
  submitDisabled = false,
  error,
  onDetailsChange,
  onSubmit,
  onCancel,
}: FeedbackFormProps) {
  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <div className="flex flex-col gap-1">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          {title}
        </h2>
        {description ? (
          <p className="text-text-neutral-secondary text-sm">{description}</p>
        ) : null}
      </div>
      <Textarea
        aria-label={detailsLabel}
        placeholder={placeholder}
        value={details}
        maxLength={detailsMaxLength}
        disabled={isSubmitting}
        onChange={(event) => onDetailsChange(event.target.value)}
        textareaSize="lg"
        className="min-h-32"
      />
      {error ? (
        <p role="alert" className="text-text-error text-sm">
          {error}
        </p>
      ) : null}
      {onCancel ? (
        <div className="flex justify-end gap-2">
          <Button
            type="button"
            variant="outline"
            disabled={isSubmitting}
            onClick={onCancel}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={isSubmitting || submitDisabled}>
            {isSubmitting ? "Sending..." : error ? "Retry" : submitLabel}
          </Button>
        </div>
      ) : (
        <Button type="submit" disabled={isSubmitting || submitDisabled}>
          {isSubmitting ? "Sending..." : error ? "Retry" : submitLabel}
        </Button>
      )}
    </form>
  );
}
