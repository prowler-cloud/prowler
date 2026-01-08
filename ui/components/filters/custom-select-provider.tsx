"use client";

import { Select, SelectItem } from "@heroui/select";
import { useRouter, useSearchParams } from "next/navigation";
import { ReactElement } from "react";

import { PROVIDER_TYPES, ProviderType } from "@/types/providers";

import {
  CustomProviderInputAlibabaCloud,
  CustomProviderInputAWS,
  CustomProviderInputAzure,
  CustomProviderInputGCP,
  CustomProviderInputGitHub,
  CustomProviderInputIac,
  CustomProviderInputKubernetes,
  CustomProviderInputM365,
  CustomProviderInputMongoDBAtlas,
  CustomProviderInputOracleCloud,
} from "./custom-provider-inputs";

const providerDisplayData: Record<
  ProviderType,
  { label: string; component: ReactElement }
> = {
  aws: {
    label: "Amazon Web Services",
    component: <CustomProviderInputAWS />,
  },
  azure: {
    label: "Microsoft Azure",
    component: <CustomProviderInputAzure />,
  },
  gcp: {
    label: "Google Cloud Platform",
    component: <CustomProviderInputGCP />,
  },
  github: {
    label: "GitHub",
    component: <CustomProviderInputGitHub />,
  },
  iac: {
    label: "Infrastructure as Code",
    component: <CustomProviderInputIac />,
  },
  kubernetes: {
    label: "Kubernetes",
    component: <CustomProviderInputKubernetes />,
  },
  m365: {
    label: "Microsoft 365",
    component: <CustomProviderInputM365 />,
  },
  mongodbatlas: {
    label: "MongoDB Atlas",
    component: <CustomProviderInputMongoDBAtlas />,
  },
  oraclecloud: {
    label: "Oracle Cloud Infrastructure",
    component: <CustomProviderInputOracleCloud />,
  },
  alibabacloud: {
    label: "Alibaba Cloud",
    component: <CustomProviderInputAlibabaCloud />,
  },
};

const dataInputsProvider = PROVIDER_TYPES.map((providerType) => ({
  key: providerType,
  label: providerDisplayData[providerType].label,
  value: providerDisplayData[providerType].component,
}));

export const CustomSelectProvider = () => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const applyProviderFilter = (value: string) => {
    const params = new URLSearchParams(searchParams.toString());
    if (value) {
      params.set("filter[provider_type]", value);
    } else {
      params.delete("filter[provider_type]");
    }
    router.push(`?${params.toString()}`, { scroll: false });
  };

  const currentProvider = searchParams.get("filter[provider_type]") || "";

  const selectedKeys = dataInputsProvider.some(
    (provider) => provider.key === currentProvider,
  )
    ? [currentProvider]
    : [];

  return (
    <Select
      items={dataInputsProvider}
      aria-label="Select a Provider"
      placeholder="Select a provider"
      classNames={{
        selectorIcon: "right-2",
        label: "z-0! mb-2",
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
