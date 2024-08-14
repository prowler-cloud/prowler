"use client";

import { Select, SelectItem } from "@nextui-org/react";

import {
  CustomProviderInputAWS,
  CustomProviderInputAzure,
  CustomProviderInputGCP,
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
    value: <CustomProviderInputGCP />,
  },
];

export const CustomSelectProvider = () => {
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
