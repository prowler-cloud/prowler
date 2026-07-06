import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { ProviderGroup } from "@/types/components";
import type { ProviderProps } from "@/types/providers";

import { CrossProviderFilters } from "./cross-provider-filters";

const { providerAccountSelectorsProps, providerGroupSelectorProps } =
  vi.hoisted(() => ({
    providerAccountSelectorsProps: {
      value: undefined as { providers: ProviderProps[] } | undefined,
    },
    providerGroupSelectorProps: {
      value: undefined as { groups: ProviderGroup[] } | undefined,
    },
  }));

// This wrapper's own job is just "render the shared filter controls when
// there's something to filter" — the controls' own instant/batch/URL
// behaviour is already covered by provider-account-selectors.test.tsx and
// provider-group-selector.test.tsx.
vi.mock("@/components/filters/provider-account-selectors", () => ({
  ProviderAccountSelectors: (props: { providers: ProviderProps[] }) => {
    providerAccountSelectorsProps.value = props;
    return <div>Provider account selectors</div>;
  },
}));

vi.mock("@/components/filters/provider-group-selector", () => ({
  ProviderGroupSelector: (props: { groups: ProviderGroup[] }) => {
    providerGroupSelectorProps.value = props;
    return <div>Provider group selector</div>;
  },
}));

vi.mock("@/components/filters/clear-filters-button", () => ({
  ClearFiltersButton: ({ showCount }: { showCount?: boolean }) => (
    <button type="button">Clear all{showCount ? " (with count)" : ""}</button>
  ),
}));

const makeProvider = (id: string, provider: string): ProviderProps =>
  ({
    id,
    type: "providers",
    attributes: { provider },
  }) as unknown as ProviderProps;

const makeGroup = (id: string, name: string): ProviderGroup =>
  ({
    id,
    type: "provider-groups",
    attributes: { name },
  }) as unknown as ProviderGroup;

describe("CrossProviderFilters", () => {
  it("renders nothing when there are no compatible providers", () => {
    const { container } = render(
      <CrossProviderFilters providers={[]} providerGroups={[]} />,
    );

    expect(container).toBeEmptyDOMElement();
  });

  it("renders the provider account selectors, group selector and clear-filters button when providers exist", () => {
    const providers = [makeProvider("azure-1", "azure")];

    render(<CrossProviderFilters providers={providers} providerGroups={[]} />);

    expect(screen.getByText("Provider account selectors")).toBeInTheDocument();
    expect(screen.getByText("Provider group selector")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /clear all/i }),
    ).toBeInTheDocument();
  });

  it("passes the compatible providers straight through to the account selectors", () => {
    const providers = [
      makeProvider("azure-1", "azure"),
      makeProvider("gcp-1", "gcp"),
    ];

    render(<CrossProviderFilters providers={providers} providerGroups={[]} />);

    expect(providerAccountSelectorsProps.value?.providers).toEqual(providers);
  });

  it("passes every tenant provider group straight through to the group selector", () => {
    // Unlike ``providers``, groups are NOT narrowed to the framework's
    // compatible provider types — a group can span multiple types, same as
    // every other provider-group filter in the app.
    const providers = [makeProvider("azure-1", "azure")];
    const providerGroups = [makeGroup("group-1", "Production")];

    render(
      <CrossProviderFilters
        providers={providers}
        providerGroups={providerGroups}
      />,
    );

    expect(providerGroupSelectorProps.value?.groups).toEqual(providerGroups);
  });

  it("shows the active-filter count on the clear button", () => {
    // Regression guard: dropping ``showCount`` would silently hide how many
    // filters are active, matching how every other filter bar in the app
    // surfaces it (findings, resources, scans).
    render(
      <CrossProviderFilters
        providers={[makeProvider("azure-1", "azure")]}
        providerGroups={[]}
      />,
    );

    expect(screen.getByText(/with count/)).toBeInTheDocument();
  });
});
