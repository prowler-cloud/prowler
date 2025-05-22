import { ProviderAccountProps, ProviderProps } from "@/types/providers";

export const extractProviderUIDs = (providersData: any): string[] => {
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
  providersData: any,
): Array<{ [uid: string]: ProviderAccountProps }> => {
  if (!providersData?.data) return [];

  return providerUIDs.map((uid) => {
    const provider = providersData.data.find(
      (p: { attributes: { uid: string } }) => p.attributes?.uid === uid,
    );

    return {
      [uid]: {
        provider: provider?.attributes?.provider || "",
        uid: uid,
        alias: provider?.attributes?.alias ?? null,
      },
    };
  });
};
