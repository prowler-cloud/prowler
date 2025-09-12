"use client";

import { Select, SelectItem } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useMemo } from "react";

import { PROVIDER_TYPES, ProviderType } from "@/types/providers";

import {
  CustomProviderInputAWS,
  CustomProviderInputAzure,
  CustomProviderInputGCP,
  CustomProviderInputGitHub,
  CustomProviderInputKubernetes,
  CustomProviderInputM365,
} from "./custom-provider-inputs";

const providerDisplayData: Record<
  ProviderType,
  { label: string; component: React.ReactElement }
> = {
  aws: {
    label: "Amazon Web Services",
    component: <CustomProviderInputAWS />,
  },
  gcp: {
    label: "Google Cloud Platform",
    component: <CustomProviderInputGCP />,
  },
  azure: {
    label: "Microsoft Azure",
    component: <CustomProviderInputAzure />,
  },
  m365: {
    label: "Microsoft 365",
    component: <CustomProviderInputM365 />,
  },
  kubernetes: {
    label: "Kubernetes",
    component: <CustomProviderInputKubernetes />,
  },
  github: {
    label: "GitHub",
    component: <CustomProviderInputGitHub />,
  },
};

const dataInputsProvider = PROVIDER_TYPES.map((providerType) => ({
  key: providerType,
  label: providerDisplayData[providerType].label,
  value: providerDisplayData[providerType].component,
}));

export const CustomSelectProvider: React.FC = () => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const applyProviderFilter = useCallback(
    (value: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (value) {
        params.set("filter[provider_type]", value);
      } else {
        params.delete("filter[provider_type]");
      }
      router.push(`?${params.toString()}`, { scroll: false });
    },
    [router, searchParams],
  );

  const currentProvider = searchParams.get("filter[provider_type]") || "";

  const selectedKeys = useMemo(() => {
    return dataInputsProvider.some(
      (provider) => provider.key === currentProvider,
    )
      ? [currentProvider]
      : [];
  }, [currentProvider]);

  return (
    <Select
      items={dataInputsProvider}
      aria-label="Select a Provider"
      placeholder="Select a provider"
      classNames={{
        selectorIcon: "right-2",
        label: "!z-0 mb-2",
      }}
      label="Provider"
      labelPlacement="inside"
      size="sm"
      onChange={(e) => {
        const value = e.target.value;
        applyProviderFilter(value);
      }}
      selectedKeys={selectedKeys}
      renderValue={(items) => {
        return items.map((item) => (
          <div key={item.key} className="flex items-center gap-2">
            {item.data?.value}
          </div>
        ));
      }}
    >
      {(item) => (
        <SelectItem key={item.key} textValue={item.key} aria-label={item.label}>
          <div className="flex items-center gap-2">{item.value}</div>
        </SelectItem>
      )}
    </Select>
  );
};
