"use client";

import { useSearchParams } from "next/navigation";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
import { useUrlFilters } from "@/hooks/use-url-filters";
import type { ProviderProps } from "@/types/providers";

const ACCOUNT_FILTER_KEY = {
  PROVIDER_ID: "provider_id__in",
  PROVIDER_UID: "provider_uid__in",
} as const;

const ACCOUNT_VALUE = {
  ID: "id",
  UID: "uid",
} as const;

type AccountFilterKey =
  (typeof ACCOUNT_FILTER_KEY)[keyof typeof ACCOUNT_FILTER_KEY];
type AccountValue = (typeof ACCOUNT_VALUE)[keyof typeof ACCOUNT_VALUE];

interface ProviderAccountSelectorsBaseProps {
  providers: ProviderProps[];
  accountFilterKey?: AccountFilterKey;
  accountValue?: AccountValue;
  providerSelectorClassName?: string;
  accountSelectorClassName?: string;
  paramsToDeleteOnChange?: string[];
}

interface ProviderAccountSelectorsInstantProps
  extends ProviderAccountSelectorsBaseProps {
  mode?: "instant";
  selectedProviderTypes?: never;
  selectedAccounts?: never;
  onBatchChange?: never;
}

interface ProviderAccountSelectorsBatchProps
  extends ProviderAccountSelectorsBaseProps {
  mode: "batch";
  selectedProviderTypes: string[];
  selectedAccounts: string[];
  onBatchChange: (filterKey: string, values: string[]) => void;
}

type ProviderAccountSelectorsProps =
  | ProviderAccountSelectorsInstantProps
  | ProviderAccountSelectorsBatchProps;

const toFilterKey = (filterKey: string) => `filter[${filterKey}]`;

const getAccountValue = (
  provider: ProviderProps,
  accountValue: AccountValue,
): string =>
  accountValue === ACCOUNT_VALUE.UID ? provider.attributes.uid : provider.id;

const getCsvValues = (value: string | null): string[] =>
  value ? value.split(",").filter(Boolean) : [];

const getFilteredProviders = (
  providers: ProviderProps[],
  selectedProviderTypes: string[],
): ProviderProps[] => {
  if (selectedProviderTypes.length === 0) return providers;

  return providers.filter((provider) =>
    selectedProviderTypes.includes(provider.attributes.provider),
  );
};

const getCompatibleAccounts = ({
  providers,
  selectedAccounts,
  selectedProviderTypes,
  accountValue,
}: {
  providers: ProviderProps[];
  selectedAccounts: string[];
  selectedProviderTypes: string[];
  accountValue: AccountValue;
}): string[] => {
  if (selectedAccounts.length === 0) return [];
  if (selectedProviderTypes.length === 0) return selectedAccounts;

  const compatibleValues = new Set(
    getFilteredProviders(providers, selectedProviderTypes).map((provider) =>
      getAccountValue(provider, accountValue),
    ),
  );

  return selectedAccounts.filter((account) => compatibleValues.has(account));
};

export function ProviderAccountSelectors({
  providers,
  accountFilterKey = ACCOUNT_FILTER_KEY.PROVIDER_ID,
  accountValue = ACCOUNT_VALUE.ID,
  providerSelectorClassName,
  accountSelectorClassName,
  paramsToDeleteOnChange = [],
  ...props
}: ProviderAccountSelectorsProps) {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();
  const isBatchMode = props.mode === "batch";
  const selectedProviderTypes = isBatchMode
    ? props.selectedProviderTypes
    : getCsvValues(searchParams.get(toFilterKey("provider_type__in")));
  const selectedAccounts = isBatchMode
    ? props.selectedAccounts
    : getCsvValues(searchParams.get(toFilterKey(accountFilterKey)));
  const filteredProviders = getFilteredProviders(
    providers,
    selectedProviderTypes,
  );

  const handleProviderTypeChange = (
    filterKey: string,
    values: string[],
  ): void => {
    const compatibleAccounts = getCompatibleAccounts({
      providers,
      selectedAccounts,
      selectedProviderTypes: values,
      accountValue,
    });

    if (isBatchMode) {
      props.onBatchChange(filterKey, values);

      if (compatibleAccounts.length !== selectedAccounts.length) {
        props.onBatchChange(accountFilterKey, compatibleAccounts);
      }

      return;
    }

    navigateWithParams((params) => {
      const providerFilterKey = toFilterKey(filterKey);
      const accountUrlFilterKey = toFilterKey(accountFilterKey);

      if (values.length > 0) {
        params.set(providerFilterKey, values.join(","));
      } else {
        params.delete(providerFilterKey);
      }

      if (compatibleAccounts.length > 0) {
        params.set(accountUrlFilterKey, compatibleAccounts.join(","));
      } else {
        params.delete(accountUrlFilterKey);
      }

      paramsToDeleteOnChange.forEach((key) => params.delete(key));
    });
  };

  const handleAccountChange = (filterKey: string, values: string[]): void => {
    if (isBatchMode) {
      props.onBatchChange(filterKey, values);
      return;
    }

    navigateWithParams((params) => {
      const accountUrlFilterKey = toFilterKey(filterKey);

      if (values.length > 0) {
        params.set(accountUrlFilterKey, values.join(","));
      } else {
        params.delete(accountUrlFilterKey);
      }

      paramsToDeleteOnChange.forEach((key) => params.delete(key));
    });
  };

  return (
    <>
      <div className={providerSelectorClassName}>
        <ProviderTypeSelector
          providers={providers}
          onBatchChange={handleProviderTypeChange}
          selectedValues={selectedProviderTypes}
        />
      </div>
      <div className={accountSelectorClassName}>
        <AccountsSelector
          providers={filteredProviders}
          filterKey={accountFilterKey}
          onBatchChange={handleAccountChange}
          selectedValues={selectedAccounts}
        />
      </div>
    </>
  );
}
