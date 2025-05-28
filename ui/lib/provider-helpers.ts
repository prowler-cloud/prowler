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
