"use client";

import { Select, SelectItem } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import {
  CustomProviderInputAWS,
  CustomProviderInputAzure,
  CustomProviderInputGCP,
  CustomProviderInputKubernetes,
} from "./CustomProviderInputs";

const dataInputsProvider = [
  {
    key: "aws",
    label: "Amazon Web Services",
    value: <CustomProviderInputAWS />,
  },
  {
    key: "gcp",
    label: "Google Cloud Platform",
    value: <CustomProviderInputGCP />,
  },
  {
    key: "azure",
    label: "Microsoft Azure",
    value: <CustomProviderInputAzure />,
  },
  {
    key: "kubernetes",
    label: "Kubernetes",
    value: <CustomProviderInputKubernetes />,
  },
];

export const CustomSelectProvider = () => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [selectedProvider, setSelectedProvider] = useState("");

  const applyProviderFilter = useCallback(
    (value: string) => {
      const params = new URLSearchParams(searchParams.toString());
      if (value) {
        params.set("filter[provider]", value);
      } else {
        params.delete("filter[provider]");
      }
      router.push(`?${params.toString()}`, { scroll: false });
    },
    [router, searchParams],
  );

  useEffect(() => {
    const providerFromUrl = searchParams.get("filter[provider]") || "";
    setSelectedProvider(providerFromUrl);
  }, [searchParams]);

  return (
    <Select
      items={dataInputsProvider}
      label="Select a Provider"
      placeholder="Select a provider"
      labelPlacement="inside"
      size="sm"
      classNames={{
        base: "w-full",
        trigger: "h-12",
      }}
      onChange={(e) => {
        const value = e.target.value;
        setSelectedProvider(value);
        applyProviderFilter(value);
      }}
      selectedKeys={selectedProvider ? [selectedProvider] : []}
      renderValue={(items) => {
        return items.map((item) => {
          return (
            <div key={item.key} className="flex items-center gap-2">
              {item.data?.value}
            </div>
          );
        });
      }}
    >
      {(item) => (
        <SelectItem key={item.key} textValue={item.key} aria-label={item.label}>
          <div className="flex gap-2 items-center">{item.value}</div>
        </SelectItem>
      )}
    </Select>
  );
};
