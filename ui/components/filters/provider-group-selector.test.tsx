import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ProviderGroup } from "@/types/components";

import { ProviderGroupSelector } from "./provider-group-selector";

const multiSelectContentSpy = vi.fn();

const { navigateWithParamsMock } = vi.hoisted(() => ({
  navigateWithParamsMock: vi.fn(),
}));

let currentSearchParams = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useSearchParams: () => currentSearchParams,
}));

vi.mock("@/hooks/use-url-filters", () => ({
  useUrlFilters: () => ({
    navigateWithParams: navigateWithParamsMock,
  }),
}));

vi.mock("@/components/shadcn/select/multiselect", () => ({
  MultiSelect: ({
    children,
    onValuesChange,
  }: {
    children: React.ReactNode;
    onValuesChange: (values: string[]) => void;
  }) => (
    <div>
      <button
        data-testid="mock-select-group-2"
        onClick={() => onValuesChange(["group-2"])}
      />
      {children}
    </div>
  ),
  MultiSelectTrigger: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="trigger">{children}</div>
  ),
  MultiSelectValue: ({ placeholder }: { placeholder: string }) => (
    <span>{placeholder}</span>
  ),
  MultiSelectContent: ({
    children,
    search,
  }: {
    children: React.ReactNode;
    search?: unknown;
  }) => {
    multiSelectContentSpy(search);
    return <div>{children}</div>;
  },
  MultiSelectItem: ({
    children,
    value,
    keywords,
  }: {
    children: React.ReactNode;
    value: string;
    keywords?: string[];
  }) => (
    <div data-value={value} data-keywords={keywords?.join("|")}>
      {children}
    </div>
  ),
}));

const makeGroup = (id: string, name: string): ProviderGroup => ({
  type: "provider-groups",
  id,
  attributes: { name, inserted_at: "", updated_at: "" },
  relationships: {
    providers: { meta: { count: 0 }, data: [] },
    roles: { meta: { count: 0 }, data: [] },
  },
  links: { self: "" },
});

const groups = [
  makeGroup("group-1", "Production"),
  makeGroup("group-2", "Dev"),
];

describe("ProviderGroupSelector", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    currentSearchParams = new URLSearchParams();
  });

  it("stays visible with the placeholder and empty message when there are no provider groups", () => {
    render(<ProviderGroupSelector groups={[]} />);

    // Control is still rendered (visible even with zero groups)...
    expect(screen.getByText("All Provider Groups")).toBeInTheDocument();
    // ...and the single empty state is the MultiSelect's own emptyMessage,
    // not a duplicate custom message.
    expect(multiSelectContentSpy).toHaveBeenCalledWith({
      placeholder: "Search Provider Groups...",
      emptyMessage: "No Provider Groups found.",
    });
    expect(
      screen.queryByText("No Provider Groups available"),
    ).not.toBeInTheDocument();
  });

  it("passes searchable dropdown defaults to MultiSelectContent and lists groups", () => {
    render(<ProviderGroupSelector groups={groups} />);

    expect(multiSelectContentSpy).toHaveBeenCalledWith({
      placeholder: "Search Provider Groups...",
      emptyMessage: "No Provider Groups found.",
    });
    expect(screen.getByText("Production")).toBeInTheDocument();
    expect(screen.getByText("Dev")).toBeInTheDocument();
  });

  it("allows disabling search explicitly", () => {
    render(<ProviderGroupSelector groups={groups} search={false} />);

    expect(multiSelectContentSpy).toHaveBeenLastCalledWith(false);
  });

  it("passes the group name as a search keyword", () => {
    render(<ProviderGroupSelector groups={groups} />);

    expect(
      screen.getByText("Production").closest("[data-value]"),
    ).toHaveAttribute("data-keywords", expect.stringContaining("Production"));
  });

  it("disables select all when nothing is selected", () => {
    render(<ProviderGroupSelector groups={groups} />);

    expect(
      screen.getByRole("option", { name: /select all Provider Groups/i }),
    ).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("All selected")).toBeInTheDocument();
  });

  it("shows the selected count in the trigger when multiple groups are selected", () => {
    render(
      <ProviderGroupSelector
        groups={groups}
        onBatchChange={vi.fn()}
        selectedValues={["group-1", "group-2"]}
      />,
    );

    const trigger = screen.getByTestId("trigger");
    expect(
      within(trigger).getByText("2 Provider Groups selected"),
    ).toBeInTheDocument();
  });

  it("shows the single group name in the trigger when one group is selected", () => {
    render(
      <ProviderGroupSelector
        groups={groups}
        onBatchChange={vi.fn()}
        selectedValues={["group-1"]}
      />,
    );

    const trigger = screen.getByTestId("trigger");
    expect(within(trigger).getByText("Production")).toBeInTheDocument();
  });

  it("instant mode: writes the selection to filter[provider_groups__in] in the URL", () => {
    render(<ProviderGroupSelector groups={groups} />);

    fireEvent.click(screen.getByTestId("mock-select-group-2"));

    expect(navigateWithParamsMock).toHaveBeenCalledTimes(1);
    const params = new URLSearchParams();
    navigateWithParamsMock.mock.calls[0][0](params);
    expect(params.get("filter[provider_groups__in]")).toBe("group-2");
  });

  it("instant mode: clearing deletes the filter key and the extra paramsToDeleteOnChange keys", () => {
    currentSearchParams = new URLSearchParams(
      "filter[provider_groups__in]=group-1&page=3&scanId=abc",
    );
    render(
      <ProviderGroupSelector
        groups={groups}
        paramsToDeleteOnChange={["page", "scanId"]}
      />,
    );

    fireEvent.click(
      screen.getByRole("option", { name: /select all Provider Groups/i }),
    );

    expect(navigateWithParamsMock).toHaveBeenCalledTimes(1);
    const params = new URLSearchParams(
      "filter[provider_groups__in]=group-1&page=3&scanId=abc",
    );
    navigateWithParamsMock.mock.calls[0][0](params);
    expect(params.has("filter[provider_groups__in]")).toBe(false);
    expect(params.has("page")).toBe(false);
    expect(params.has("scanId")).toBe(false);
  });

  it("does not navigate on clear when nothing is selected", () => {
    render(<ProviderGroupSelector groups={groups} />);

    fireEvent.click(
      screen.getByRole("option", { name: /select all Provider Groups/i }),
    );

    expect(navigateWithParamsMock).not.toHaveBeenCalled();
  });
});
