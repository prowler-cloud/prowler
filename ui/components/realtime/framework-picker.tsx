"use client";

import { X } from "lucide-react";
import { useId, useState } from "react";

import { Badge } from "@/components/shadcn/badge/badge";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Input } from "@/components/shadcn/input/input";
import { frameworkLabel } from "@/lib/realtime/display";
import {
  REALTIME_MAX_FRAMEWORKS,
  type RealtimeFramework,
} from "@/types/realtime";

interface FrameworkPickerProps {
  /** The catalog; empty while it loads or when it could not be loaded. */
  catalog: RealtimeFramework[];
  selected: string[];
  disabled?: boolean;
  error?: string;
  onChange: (frameworks: string[]) => void;
}

const MAX_LISTED = 50;

const optionLabel = (framework: RealtimeFramework) =>
  framework.version
    ? `${framework.name} (${framework.version})`
    : framework.name;

/**
 * Search and chips for the compliance frameworks a policy enforces. At most
 * five; every selected id stays visible as a chip even if the catalog does not
 * know it (an id saved earlier), so it can always be removed.
 */
export function FrameworkPicker({
  catalog,
  selected,
  disabled = false,
  error,
  onChange,
}: FrameworkPickerProps) {
  const id = useId();
  const [query, setQuery] = useState("");
  const full = selected.length >= REALTIME_MAX_FRAMEWORKS;

  const needle = query.trim().toLowerCase();
  const matches = catalog
    .filter(
      (framework) =>
        !selected.includes(framework.id) &&
        (!needle ||
          framework.name.toLowerCase().includes(needle) ||
          framework.id.toLowerCase().includes(needle)),
    )
    .slice(0, MAX_LISTED);

  const remove = (frameworkId: string) =>
    onChange(selected.filter((item) => item !== frameworkId));
  const add = (frameworkId: string) => {
    if (full || selected.includes(frameworkId)) return;
    onChange([...selected, frameworkId]);
    setQuery("");
  };

  return (
    <Field>
      <FieldLabel htmlFor={`${id}-search`}>
        Enforce compliance frameworks
      </FieldLabel>

      {selected.length > 0 ? (
        <ul className="flex flex-wrap gap-2" aria-label="Enforced frameworks">
          {selected.map((frameworkId) => (
            <li key={frameworkId}>
              <Badge variant="tag" className="gap-1.5 py-1 pr-1">
                {frameworkLabel(frameworkId, catalog)}
                <button
                  type="button"
                  disabled={disabled}
                  aria-label={`Remove ${frameworkLabel(frameworkId, catalog)}`}
                  className="hover:bg-bg-neutral-tertiary rounded-full p-0.5 disabled:cursor-not-allowed disabled:opacity-50"
                  onClick={() => remove(frameworkId)}
                >
                  <X aria-hidden="true" className="size-3" />
                </button>
              </Badge>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-text-neutral-secondary text-sm">
          No framework selected: every check is in scope.
        </p>
      )}

      <Input
        id={`${id}-search`}
        type="search"
        value={query}
        disabled={disabled || full}
        placeholder={
          full
            ? `Limit reached (${REALTIME_MAX_FRAMEWORKS})`
            : "Search frameworks, for example SOC 2"
        }
        aria-describedby={`${id}-hint`}
        onChange={(event) => setQuery(event.target.value)}
      />

      {!full && !disabled && (needle || catalog.length > 0) && (
        <ul
          aria-label="Available frameworks"
          className="border-border-neutral-secondary max-h-56 overflow-y-auto rounded-lg border"
        >
          {matches.length === 0 ? (
            <li className="text-text-neutral-tertiary px-3 py-2 text-sm">
              {catalog.length === 0
                ? "The framework list is not available right now."
                : "No framework matches your search."}
            </li>
          ) : (
            matches.map((framework) => (
              <li key={framework.id}>
                <button
                  type="button"
                  className="hover:bg-bg-neutral-secondary text-text-neutral-primary w-full px-3 py-2 text-left text-sm"
                  onClick={() => add(framework.id)}
                >
                  {optionLabel(framework)}
                </button>
              </li>
            ))
          )}
        </ul>
      )}

      <p
        id={`${id}-hint`}
        className="text-text-neutral-tertiary max-w-prose text-xs"
      >
        Choose up to {REALTIME_MAX_FRAMEWORKS}. When frameworks are selected,
        remediation (account fixes and pull requests) acts only on checks that
        belong to them, for new events and for drift already present in the
        account (checked about every 10 minutes). Everything else is only
        detected and alerted. Leave empty to cover every check.
      </p>
      {error && <FieldError>{error}</FieldError>}
    </Field>
  );
}
