export interface RealtimeProviderOption {
  id: string;
  uid: string;
  alias: string | null;
}

/** The provider to show: the one in the URL when it is an AWS provider, else the first. */
export const resolveProviderId = (
  providers: RealtimeProviderOption[],
  requested?: string,
): string | undefined =>
  providers.find((provider) => provider.id === requested)?.id ??
  providers[0]?.id;

export const providerLabel = (provider: RealtimeProviderOption): string =>
  provider.alias ? `${provider.alias} (${provider.uid})` : provider.uid;
