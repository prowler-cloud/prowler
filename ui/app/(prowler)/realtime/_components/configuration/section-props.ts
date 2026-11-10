import type { FieldValues, Path, UseFormSetError } from "react-hook-form";

import type { StepState } from "@/app/(prowler)/realtime/_lib/setup";
import type { RealtimeFailure } from "@/app/(prowler)/realtime/_types";
import { toast } from "@/components/shadcn/toast";

/** What the page gives every configuration section. */
export interface SectionBaseProps {
  providerId: string;
  number: number;
  state: StepState;
  required: boolean;
  open: boolean;
  canManage: boolean;
  onOpen: () => void;
  onClose: () => void;
  /** After a successful save: the page re-reads the setup. */
  onSaved: () => void;
}

/** API field errors onto the form; a failure with none becomes a toast. */
export const reportSaveFailure = <T extends FieldValues>(
  failure: RealtimeFailure,
  setError: UseFormSetError<T>,
  fields: readonly string[],
  title: string,
) => {
  const mapped = Object.entries(failure.fieldErrors ?? {}).filter(([field]) =>
    fields.includes(field),
  );
  mapped.forEach(([field, message]) =>
    setError(field as Path<T>, { type: "server", message }),
  );
  if (mapped.length === 0) {
    toast({ variant: "destructive", title, description: failure.error });
  }
};
