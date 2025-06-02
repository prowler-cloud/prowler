import { IncludeProps, ScanProps } from "@/types";
import {
  ProviderProps,
  ProvidersApiResponse,
  ProviderType,
} from "@/types/providers";

export const extractProviderUIDs = (
  providersData: ProvidersApiResponse,
): string[] => {
  if (!providersData?.data) return [];

  return Array.from(
    new Set(
      providersData.data
        .map((provider: ProviderProps) => provider.attributes?.uid)
        .filter(Boolean),
    ),
  );
};

export const createProviderDetailsMapping = (
  providerUIDs: string[],
  providersData: ProvidersApiResponse,
): Array<{
  [uid: string]: {
    providerInfo: {
      provider: ProviderType;
      alias?: string;
      uid?: string;
    };
  };
}> => {
  if (!providersData?.data) return [];

  return providerUIDs.map((uid) => {
    const provider = providersData.data.find(
      (p: { attributes: { uid: string } }) => p.attributes?.uid === uid,
    );

    return {
      [uid]: {
        providerInfo: {
          provider: provider?.attributes?.provider || "aws",
          uid: uid,
          alias: provider?.attributes?.alias,
        },
      },
    };
  });
};

/**
 * Extracts and formats provider details associated with a given scan.
 *
 * @param scan - The scan object containing scan attributes and provider relationship data.
 * @param included - An array of included related resources (e.g., providers).
 * @param format - Optional. Specifies the structure of the returned object.
 *                 - "keyed" (default): Returns an object keyed by scan ID with providerInfo and attributes.
 *                 - "flat": Returns a flat object containing providerInfo and attributes.
 *                 - "merged": Returns the full scan object with providerInfo merged in.
 *
 * @returns An object containing provider information and scan attributes in the specified format.
 *
 * @example
 * const result = getProviderDetailsByScan(scan, included, "flat");
 * // {
 * //   providerInfo: { provider: 'Example Provider', alias: 'EP', uid: '123' },
 * //   attributes: { name: 'Scan 1', started_at: '2024-01-01', completed_at: '2024-01-02' }
 * // }
 */
export const getProviderDetailsByScan = (
  scan: ScanProps,
  included: IncludeProps[],
  format: "keyed" | "flat" | "merged" = "keyed",
) => {
  const providerId = scan.relationships?.provider?.data?.id;

  const providerDetails = providerId
    ? included.find(
        (provider) =>
          provider.type === "providers" && provider.id === providerId,
      )
    : null;

  const providerInfo = {
    provider: providerDetails?.attributes?.provider,
    alias: providerDetails?.attributes?.alias ?? null,
    uid: providerDetails?.attributes?.uid ?? null,
  };

  const attributes = {
    name: scan.attributes?.name,
    started_at: scan.attributes?.started_at,
    completed_at: scan.attributes?.completed_at,
  };

  // --- FORMAT 1: keyed (default)
  if (format === "keyed") {
    return {
      [scan.id]: {
        providerInfo,
        attributes,
      },
    };
  }

  // --- FORMAT 2: flat object
  if (format === "flat") {
    return {
      providerInfo,
      attributes,
    };
  }

  // --- FORMAT 3: merged into full scan object
  if (format === "merged") {
    return {
      ...scan,
      providerInfo,
    };
  }
};
