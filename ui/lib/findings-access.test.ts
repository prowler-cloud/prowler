import { describe, expect, it } from "vitest";

import {
  FINDINGS_PREVIEW_ROW_LIMIT,
  isFindingsPreviewLocked,
} from "./findings-access";

describe("findings access", () => {
  it("never locks the findings preview on self-hosted deployments", async () => {
    // Given / When
    const locked = await isFindingsPreviewLocked();

    // Then
    expect(locked).toBe(false);
  });

  it("previews the ten most critical finding groups when locked", () => {
    expect(FINDINGS_PREVIEW_ROW_LIMIT).toBe(10);
  });
});
