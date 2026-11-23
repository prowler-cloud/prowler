import {
  type ActionErrorResult,
  getActionErrorMessage,
  hasActionError,
} from "@/lib/action-errors";
import type { PartialScanTarget } from "@/types/partial-scans";
import type { ProviderProps } from "@/types/providers";

export const PARTIAL_SCAN_LAUNCH_ERROR =
  "The re-check could not be launched. Please try again.";

interface PartialScanAvailability {
  cloudEnabled: boolean;
  canManageScans: boolean;
}

/** Partial scans are a Cloud feature that needs the manage_scans permission. */
export const isPartialScanAvailable = ({
  cloudEnabled,
  canManageScans,
}: PartialScanAvailability): boolean => cloudEnabled && canManageScans;

const isMeaningful = (value: string | undefined): value is string =>
  typeof value === "string" && value.trim() !== "" && value !== "-";

/** A target needs a real resource uid and a way to identify its provider. */
export const isPartialScanTarget = (
  target: Partial<PartialScanTarget> | null | undefined,
): target is PartialScanTarget => {
  if (!target || !isMeaningful(target.resourceUid)) return false;
  if (isMeaningful(target.providerId)) return true;
  return isMeaningful(target.providerUid) && isMeaningful(target.providerType);
};

/** Provider uid is unique per provider type, so both together pick one row. */
export const findProviderIdForTarget = (
  providers: Pick<ProviderProps, "id" | "attributes">[],
  target: Pick<PartialScanTarget, "providerUid" | "providerType">,
): string | undefined =>
  providers.find(
    (provider) =>
      provider.attributes.uid === target.providerUid &&
      provider.attributes.provider === target.providerType,
  )?.id;

export const getPartialScanErrorMessage = (
  result: (ActionErrorResult & { data?: unknown }) | null | undefined,
): string | null =>
  hasActionError(result)
    ? getActionErrorMessage(result, { fallback: PARTIAL_SCAN_LAUNCH_ERROR })
    : null;
