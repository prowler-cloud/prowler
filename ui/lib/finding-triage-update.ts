import { updateFindingTriage } from "@/actions/findings";
import { UsageLimitError } from "@/lib/action-errors";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

/** Client-side triage write: a usage-limit refusal throws, so callers skip their local patch. */
export const updateFindingTriageOrThrow = async (
  input: UpdateFindingTriageInput,
) => {
  const result = await updateFindingTriage(input);
  if (result && typeof result === "object" && "usageLimited" in result) {
    throw new UsageLimitError();
  }
  return result;
};
