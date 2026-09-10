import { describe, expect, it } from "vitest";

import type { ProviderProps } from "@/types/providers";
import type { ScanConfigurationData } from "@/types/scan-configurations";

import { getSelectableProviders } from "./scan-configuration-providers";

const provider = (id: string, isDynamic = false): ProviderProps =>
  ({
    id,
    type: "providers",
    attributes: {
      provider: isDynamic ? "template" : "aws",
      is_dynamic: isDynamic,
    },
  }) as unknown as ProviderProps;

const config = (id: string, providers: string[]): ScanConfigurationData => ({
  type: "scan-configurations",
  id,
  attributes: {
    inserted_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    name: id,
    configuration: {},
    providers,
  },
});

describe("getSelectableProviders", () => {
  it("excludes dynamic providers (they have no config baseline to override)", () => {
    const result = getSelectableProviders(
      [provider("aws-1"), provider("dyn-1", true)],
      [],
      null,
    );

    expect(result.selectableProviders.map((p) => p.id)).toEqual(["aws-1"]);
    expect(result.configurableCount).toBe(1);
    expect(result.lockedCount).toBe(0);
  });

  it("excludes providers already attached to another config", () => {
    const result = getSelectableProviders(
      [provider("aws-1"), provider("aws-2")],
      [config("other", ["aws-2"])],
      null,
    );

    expect(result.selectableProviders.map((p) => p.id)).toEqual(["aws-1"]);
    expect(result.lockedCount).toBe(1);
  });

  it("keeps providers attached to the config being edited selectable", () => {
    const result = getSelectableProviders(
      [provider("aws-1"), provider("aws-2")],
      [config("current", ["aws-1"])],
      "current",
    );

    expect(result.selectableProviders.map((p) => p.id)).toEqual([
      "aws-1",
      "aws-2",
    ]);
    expect(result.lockedCount).toBe(0);
  });

  it("lockedCount counts only configurable providers attached elsewhere, not dynamic ones", () => {
    const result = getSelectableProviders(
      [provider("aws-1"), provider("aws-2"), provider("dyn-1", true)],
      [config("other", ["aws-2"])],
      null,
    );

    expect(result.selectableProviders.map((p) => p.id)).toEqual(["aws-1"]);
    expect(result.configurableCount).toBe(2);
    expect(result.lockedCount).toBe(1);
  });

  it("reports zero configurable providers when every provider is dynamic", () => {
    const result = getSelectableProviders(
      [provider("dyn-1", true), provider("dyn-2", true)],
      [],
      null,
    );

    expect(result.selectableProviders).toEqual([]);
    expect(result.configurableCount).toBe(0);
    expect(result.lockedCount).toBe(0);
  });
});
