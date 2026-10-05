import type { ComboboxGroup } from "@/components/shadcn/combobox";

// Keep in sync with OCI_REGIONS in prowler/providers/oraclecloud/config.py
const OCI_COMMERCIAL_REGIONS = [
  "af-casablanca-1",
  "af-johannesburg-1",
  "ap-batam-1",
  "ap-chuncheon-1",
  "ap-hyderabad-1",
  "ap-kulai-2",
  "ap-melbourne-1",
  "ap-mumbai-1",
  "ap-osaka-1",
  "ap-seoul-1",
  "ap-singapore-1",
  "ap-singapore-2",
  "ap-sydney-1",
  "ap-tokyo-1",
  "ca-montreal-1",
  "ca-toronto-1",
  "eu-amsterdam-1",
  "eu-frankfurt-1",
  "eu-madrid-1",
  "eu-madrid-3",
  "eu-marseille-1",
  "eu-milan-1",
  "eu-paris-1",
  "eu-stockholm-1",
  "eu-turin-1",
  "eu-zurich-1",
  "il-jerusalem-1",
  "me-abudhabi-1",
  "me-dubai-1",
  "me-jeddah-1",
  "me-riyadh-1",
  "mx-monterrey-1",
  "mx-queretaro-1",
  "sa-bogota-1",
  "sa-santiago-1",
  "sa-saopaulo-1",
  "sa-valparaiso-1",
  "sa-vinhedo-1",
  "uk-cardiff-1",
  "uk-london-1",
  "us-ashburn-1",
  "us-chicago-1",
  "us-phoenix-1",
  "us-sanjose-1",
];

const OCI_GOVERNMENT_REGIONS = [
  { value: "us-langley-1", label: "us-langley-1 (US Gov West)" },
  { value: "us-luke-1", label: "us-luke-1 (US Gov East)" },
  { value: "us-gov-ashburn-1", label: "us-gov-ashburn-1 (US DoD East)" },
  { value: "us-gov-chicago-1", label: "us-gov-chicago-1 (US DoD North)" },
  { value: "us-gov-phoenix-1", label: "us-gov-phoenix-1 (US DoD West)" },
];

export const OCI_REGION_GROUPS: ComboboxGroup[] = [
  {
    heading: "Commercial",
    options: OCI_COMMERCIAL_REGIONS.map((region) => ({
      value: region,
      label: region,
    })),
  },
  { heading: "Government", options: OCI_GOVERNMENT_REGIONS },
];

export const OCI_REGION_VALUES = OCI_REGION_GROUPS.flatMap((group) =>
  group.options.map((option) => option.value),
);
