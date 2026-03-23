const PROVIDER_TAB = {
  ACCOUNTS: "accounts",
  ACCOUNT_GROUPS: "account-groups",
} as const;

type ProviderTab = (typeof PROVIDER_TAB)[keyof typeof PROVIDER_TAB];

function isProviderTab(value: string): value is ProviderTab {
  return Object.values(PROVIDER_TAB).includes(value as ProviderTab);
}

function getProviderTab(value: string | string[] | undefined): ProviderTab {
  if (typeof value !== "string") {
    return PROVIDER_TAB.ACCOUNTS;
  }

  return isProviderTab(value) ? value : PROVIDER_TAB.ACCOUNTS;
}

export type { ProviderTab };
export { getProviderTab, PROVIDER_TAB };
