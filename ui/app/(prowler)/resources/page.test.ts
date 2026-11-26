import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  Children,
  isValidElement,
  type ReactElement,
  type ReactNode,
  Suspense,
} from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
  replaceFieldKey,
} from "@/lib/helper-filters";
import { createDict } from "@/lib/utils";

const {
  getResources,
  getLatestResources,
  getMetadataInfo,
  getLatestMetadataInfo,
} = vi.hoisted(() => ({
  getResources: vi.fn(),
  getLatestResources: vi.fn(),
  getMetadataInfo: vi.fn(),
  getLatestMetadataInfo: vi.fn(),
}));

vi.mock("@/actions/resources", () => ({
  getResources,
  getLatestResources,
  getMetadataInfo,
  getLatestMetadataInfo,
  getResourceById: vi.fn(),
}));
vi.mock("@/actions/providers", () => ({ getAllProviders: vi.fn() }));
vi.mock("@/actions/manage-groups/manage-groups", () => ({
  getAllProviderGroups: vi.fn(),
}));
vi.mock("@/lib", () => ({
  extractFiltersAndQuery,
  extractSortAndKey,
  hasDateOrScanFilter,
  replaceFieldKey,
  createDict,
}));
vi.mock("@/components/resources/resources-filters", () => ({
  ResourcesFilters: () => null,
}));
vi.mock("@/components/resources/skeleton/skeleton-table-resources", () => ({
  SkeletonTableResources: () => null,
}));
vi.mock("@/components/resources/table", () => ({
  ResourcesTableWithSelection: () => null,
}));
vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: () => null,
}));
vi.mock("@/contexts", () => ({ FilterTransitionWrapper: () => null }));

import Resources from "./page";

interface PageChildren {
  children: ReactNode;
}

interface ResourcesPageProps {
  children: ReactElement<PageChildren>;
}

type AsyncServerComponent = (
  props: Record<string, unknown>,
) => Promise<ReactNode>;

const loadResourcesPage = async (searchParams: Record<string, string>) => {
  const page = (await Resources({
    searchParams: Promise.resolve(searchParams),
  })) as ReactElement<ResourcesPageProps>;
  const suspense = Children.toArray(page.props.children.props.children).find(
    (child) => isValidElement(child) && child.type === Suspense,
  );
  if (!isValidElement<{ children: ReactElement }>(suspense)) {
    throw new Error("Expected the resources table Suspense boundary");
  }
  const table = suspense.props.children as ReactElement<
    Record<string, unknown>,
    AsyncServerComponent
  >;
  await table.type(table.props);
};

describe("resources page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const pagePath = path.join(currentDir, "page.tsx");
  const tablePath = path.join(
    currentDir,
    "../../../components/resources/table/resources-table-with-selection.tsx",
  );

  const pageSource = readFileSync(pagePath, "utf8");
  const tableSource = readFileSync(tablePath, "utf8");

  it("fetches the deep-linked resource on the server in parallel with the rest of the page data", () => {
    expect(pageSource).toContain("getResourceById(initialResourceId");
    expect(pageSource).toContain("await Promise.all");
    expect(pageSource).toContain("initialResource={processedResource}");
  });

  it("keeps the client table free of deep-link fetch effects", () => {
    expect(tableSource).not.toContain("useEffect");
    expect(tableSource).not.toContain("useRef");
    expect(tableSource).not.toContain("getResourceById");
    expect(tableSource).not.toContain("initialResourceId");
    expect(tableSource).toContain("initialResource?: ResourceProps | null");
  });
});

describe("resources scan drill-down fetching", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getResources.mockResolvedValue({ data: [] });
    getLatestResources.mockResolvedValue({ data: [] });
  });

  it("keeps an older scan scoped to historical resources and metadata during pagination", async () => {
    // Given
    const filters = {
      "filter[scan]": "historical-scan",
      "filter[service]": "ec2",
    };

    // When
    await loadResourcesPage({ ...filters, page: "2", pageSize: "20" });

    // Then
    expect(getResources).toHaveBeenCalledWith(
      expect.objectContaining({
        filters,
        page: 2,
        pageSize: 20,
      }),
    );
    expect(getMetadataInfo).toHaveBeenCalledWith(
      expect.objectContaining({ filters }),
    );
    expect(getLatestResources).not.toHaveBeenCalled();
    expect(getLatestMetadataInfo).not.toHaveBeenCalled();
  });

  it("uses latest resources and metadata when no scan or date scope exists", async () => {
    // Given / When
    await loadResourcesPage({});

    // Then
    expect(getLatestResources).toHaveBeenCalledOnce();
    expect(getLatestMetadataInfo).toHaveBeenCalledOnce();
    expect(getResources).not.toHaveBeenCalled();
    expect(getMetadataInfo).not.toHaveBeenCalled();
  });
});
