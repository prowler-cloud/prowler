"use client";

import type { Dispatch, FormEvent, SetStateAction } from "react";
import { useState } from "react";

import { SaveIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { Input } from "@/components/shadcn/input/input";
import { useToast } from "@/components/ui";

interface EditNameFormProps {
  currentValue: string;
  label: string;
  successMessage: string;
  placeholder?: string;
  helperText?: string;
  validate?: (value: string) => string | null;
  setIsOpen: Dispatch<SetStateAction<boolean>>;
  onSave: (value: string) => Promise<unknown>;
}

export function EditNameForm({
  currentValue,
  label,
  successMessage,
  placeholder,
  helperText,
  validate,
  setIsOpen,
  onSave,
}: EditNameFormProps) {
  const [value, setValue] = useState(currentValue);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const { toast } = useToast();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    const trimmed = value.trim();
    if (validate) {
      const validationError = validate(trimmed);
      if (validationError) {
        setError(validationError);
        return;
      }
    }

    setError(null);
    setIsLoading(true);

    const result = (await onSave(trimmed)) as Record<string, unknown>;

    setIsLoading(false);

    const errors = result?.errors as Array<{ detail: string }> | undefined;

    if (errors && errors.length > 0) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: `${errors[0].detail}`,
      });
    } else if (result?.error) {
      toast({
        variant: "destructive",
        title: "Oops! Something went wrong",
        description: String(result.error),
      });
    } else {
      toast({ title: "Success!", description: successMessage });
      setIsOpen(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <div className="text-md">
        Current {label.toLowerCase()}:{" "}
        <span className="font-bold">{currentValue || "—"}</span>
      </div>
      <div className="flex flex-col gap-2">
        <label
          htmlFor="edit-name-input"
          className="text-text-neutral-primary text-sm font-medium"
        >
          {label}
        </label>
        <Input
          id="edit-name-input"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            if (error) setError(null);
          }}
          placeholder={placeholder ?? currentValue}
          disabled={isLoading}
          aria-invalid={!!error}
        />
        {error && <p className="text-destructive text-xs">{error}</p>}
        {helperText && !error && (
          <p className="text-muted-foreground text-xs">{helperText}</p>
        )}
      </div>

      <div className="flex w-full justify-end gap-4">
        <Button
          type="button"
          variant="ghost"
          size="lg"
          onClick={() => setIsOpen(false)}
          disabled={isLoading}
        >
          Cancel
        </Button>
        <Button type="submit" size="lg" disabled={isLoading}>
          {!isLoading && <SaveIcon size={24} />}
          {isLoading ? "Loading" : "Save"}
        </Button>
      </div>
    </form>
  );
}
