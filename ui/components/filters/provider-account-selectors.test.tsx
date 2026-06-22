import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ProviderProps } from "@/types/providers";

import { ProviderAccountSelectors } from "./provider-account-selectors";

const { selectorProps, navigateWithParamsMock, currentSearchParams } =
  vi.hoisted(() => ({
    selectorProps: {
      providerType: undefined as
        | {
            providers: ProviderProps[];
            onBatchChange: (filterKey: string, values: string[]) => void;
            selectedValues: string[];
          }
        | undefined,
      accounts: undefined as
        | {
            providers: ProviderProps[];
            filterKey?: string;
            onBatchChange: (filterKey: string, values: string[]) => void;
            selectedValues: string[];
          }
        | undefined,
    },
    navigateWithParamsMock: vi.fn(),
    currentSearchParams: { value: "" },
  }));

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(currentSearchParams.value),
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({
    navigateWithParams: navigateWithParamsMock,
  }),
}));

vi.mock("@/app/(prowler)/_overview/_components/provider-type-selector", () => ({
  ProviderTypeSelector: (props: {
    providers: ProviderProps[];
    onBatchChange: (filterKey: string, values: string[]) => void;
    selectedValues: string[];
  }) => {
    selectorProps.providerType = props;
    return <div>Provider type selector</div>;
  },
}));

vi.mock("@/app/(prowler)/_overview/_components/accounts-selector", () => ({
  AccountsSelector: (props: {
    providers: ProviderProps[];
    filterKey?: string;
    onBatchChange: (filterKey: string, values: string[]) => void;
    selectedValues: string[];
  }) => {
    selectorProps.accounts = props;
    return <div>Accounts selector</div>;
  },
}));

const makeProvider = ({
  id,
  provider,
  uid,
  alias,
}: {
  id: string;
  provider: ProviderProps["attributes"]["provider"];
  uid: string;
  alias: string;
}): ProviderProps => ({
  id,
  type: "providers",
  attributes: {
    provider,
    uid,
    alias,
    status: "completed",
    resources: 0,
    connection: {
      connected: true,
      last_checked_at: "2026-04-13T00:00:00Z",
    },
    scanner_args: {
      only_logs: false,
      excluded_checks: [],
      aws_retries_max_attempts: 3,
    },
    inserted_at: "2026-04-13T00:00:00Z",
    updated_at: "2026-04-13T00:00:00Z",
    created_by: {
      object: "user",
      id: "user-1",
    },
  },
  relationships: {
    secret: { data: null },
    provider_groups: {
      meta: { count: 0 },
      data: [],
    },
  },
});

const providers = [
  makeProvider({
    id: "aws-provider",
    provider: "aws",
    uid: "123456789012",
    alias: "Production AWS",
  }),
  makeProvider({
    id: "gcp-provider",
    provider: "gcp",
    uid: "prowler-project",
    alias: "Production GCP",
  }),
];

const applyLastNavigation = () => {
  const modifier = navigateWithParamsMock.mock.calls.at(-1)?.[0] as
    | ((params: URLSearchParams) => void)
    | undefined;
  const params = new URLSearchParams(currentSearchParams.value);

  if (!modifier) throw new Error("Expected navigateWithParams to be called");

  modifier(params);

  return params;
};

describe("ProviderAccountSelectors", () => {
  beforeEach(() => {
    currentSearchParams.value = "";
    selectorProps.providerType = undefined;
    selectorProps.accounts = undefined;
    navigateWithParamsMock.mockClear();
  });

  it("filters account options by selected provider types in instant mode", () => {
    currentSearchParams.value = "filter%5Bprovider_type__in%5D=aws";

    render(<ProviderAccountSelectors providers={providers} />);

    expect(selectorProps.accounts?.providers).toEqual([providers[0]]);
  });

  it("cleans incompatible selected accounts in the same instant navigation", () => {
    currentSearchParams.value =
      "filter%5Bprovider_type__in%5D=aws&filter%5Bprovider_id__in%5D=aws-provider";

    render(<ProviderAccountSelectors providers={providers} />);

    selectorProps.providerType?.onBatchChange("provider_type__in", ["gcp"]);

    const params = applyLastNavigation();

    expect(params.get("filter[provider_type__in]")).toBe("gcp");
    expect(params.get("filter[provider_id__in]")).toBeNull();
  });

  it("cleans incompatible UID accounts in the same instant navigation", () => {
    currentSearchParams.value =
      "filter%5Bprovider_type__in%5D=aws&filter%5Bprovider_uid__in%5D=123456789012&page=2&scanId=scan-1";

    render(
      <ProviderAccountSelectors
        providers={providers}
        accountFilterKey="provider_uid__in"
        accountValue="uid"
        paramsToDeleteOnChange={["page", "scanId"]}
      />,
    );

    selectorProps.providerType?.onBatchChange("provider_type__in", ["gcp"]);

    const params = applyLastNavigation();

    expect(selectorProps.accounts?.filterKey).toBe("provider_uid__in");
    expect(params.get("filter[provider_type__in]")).toBe("gcp");
    expect(params.get("filter[provider_uid__in]")).toBeNull();
    expect(params.get("page")).toBeNull();
    expect(params.get("scanId")).toBeNull();
  });

  it("filters account options by selected provider types in batch mode", () => {
    render(
      <ProviderAccountSelectors
        providers={providers}
        mode="batch"
        selectedProviderTypes={["aws"]}
        selectedAccounts={[]}
        onBatchChange={vi.fn()}
      />,
    );

    expect(selectorProps.accounts?.providers).toEqual([providers[0]]);
  });

  it("cleans incompatible selected accounts in batch mode", () => {
    const onBatchChange = vi.fn();

    render(
      <ProviderAccountSelectors
        providers={providers}
        mode="batch"
        selectedProviderTypes={["aws"]}
        selectedAccounts={["aws-provider", "gcp-provider"]}
        onBatchChange={onBatchChange}
      />,
    );

    selectorProps.providerType?.onBatchChange("provider_type__in", ["gcp"]);

    expect(onBatchChange).toHaveBeenCalledWith("provider_type__in", ["gcp"]);
    expect(onBatchChange).toHaveBeenCalledWith("provider_id__in", [
      "gcp-provider",
    ]);
  });

  it("uses provider UID values when accountValue is uid", () => {
    const onBatchChange = vi.fn();

    render(
      <ProviderAccountSelectors
        providers={providers}
        mode="batch"
        accountFilterKey="provider_uid__in"
        accountValue="uid"
        selectedProviderTypes={["aws"]}
        selectedAccounts={["123456789012", "prowler-project"]}
        onBatchChange={onBatchChange}
      />,
    );

    selectorProps.providerType?.onBatchChange("provider_type__in", ["gcp"]);

    expect(selectorProps.accounts?.filterKey).toBe("provider_uid__in");
    expect(onBatchChange).toHaveBeenCalledWith("provider_uid__in", [
      "prowler-project",
    ]);
  });
});
