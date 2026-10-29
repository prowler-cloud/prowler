"use client";

import { useId } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import { newScopeRow, type ScopeRow } from "@/lib/realtime/policy-schema";
import { REALTIME_MAX_SCOPE_TAGS } from "@/types/realtime";

interface ScopeTagsEditorProps {
  rows: ScopeRow[];
  disabled?: boolean;
  error?: string;
  onChange: (rows: ScopeRow[]) => void;
}

/** key=value tag filters. Every row must match (AND), one value per key. */
export function ScopeTagsEditor({
  rows,
  disabled,
  error,
  onChange,
}: ScopeTagsEditorProps) {
  const groupId = useId();
  const atLimit = rows.length >= REALTIME_MAX_SCOPE_TAGS;

  const update = (id: string, patch: Partial<ScopeRow>) =>
    onChange(rows.map((row) => (row.id === id ? { ...row, ...patch } : row)));

  return (
    <fieldset
      className="flex flex-col gap-3"
      aria-describedby={`${groupId}-note`}
    >
      <legend className="text-text-neutral-primary text-sm font-medium">
        Tag scope
      </legend>
      <p
        id={`${groupId}-note`}
        className="text-text-neutral-tertiary max-w-prose text-xs"
      >
        Watch only resources that carry all of these tags (up to{" "}
        {REALTIME_MAX_SCOPE_TAGS}). Resources outside the scope are not
        evaluated, so account-wide controls such as root MFA and account-level
        settings are skipped while a scope is set. Leave it empty to watch the
        whole account.
      </p>

      {rows.map((row, index) => (
        <div
          key={row.id}
          className="grid grid-cols-1 items-end gap-2 sm:grid-cols-[1fr_1fr_auto]"
        >
          <Field>
            <FieldLabel htmlFor={`${groupId}-key-${row.id}`}>
              Tag key {index + 1}
            </FieldLabel>
            <Input
              id={`${groupId}-key-${row.id}`}
              value={row.key}
              disabled={disabled}
              placeholder="environment"
              onChange={(event) => update(row.id, { key: event.target.value })}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor={`${groupId}-value-${row.id}`}>
              Tag value {index + 1}
            </FieldLabel>
            <Input
              id={`${groupId}-value-${row.id}`}
              value={row.value}
              disabled={disabled}
              placeholder="production"
              onChange={(event) =>
                update(row.id, { value: event.target.value })
              }
            />
          </Field>
          <Button
            type="button"
            variant="outline"
            disabled={disabled}
            onClick={() => onChange(rows.filter((item) => item.id !== row.id))}
            aria-label={`Remove tag ${index + 1}`}
          >
            Remove
          </Button>
        </div>
      ))}

      {error && <FieldError>{error}</FieldError>}

      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={disabled || atLimit}
          onClick={() => onChange([...rows, newScopeRow()])}
        >
          {atLimit
            ? `Limit of ${REALTIME_MAX_SCOPE_TAGS} tags reached`
            : "Add tag"}
        </Button>
      </div>
    </fieldset>
  );
}
