const PROVIDER_TAB = {
  PROVIDERS: "providers",
  PROVIDER_GROUPS: "provider-groups",
} as const;

type ProviderTab = (typeof PROVIDER_TAB)[keyof typeof PROVIDER_TAB];

function isProviderTab(value: string): value is ProviderTab {
  return Object.values(PROVIDER_TAB).includes(value as ProviderTab);
}

function getProviderTab(value: string | string[] | undefined): ProviderTab {
  if (typeof value !== "string") {
    return PROVIDER_TAB.PROVIDERS;
  }

  return isProviderTab(value) ? value : PROVIDER_TAB.PROVIDERS;
}

export type { ProviderTab };
export { getProviderTab, PROVIDER_TAB };
