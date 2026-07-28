import { describe, expect, it } from "vitest";

import {
  toast as shadcnToast,
  Toaster as ShadcnToaster,
} from "@/components/shadcn/toast";
import { toast as uiToast, Toaster as UiToaster } from "@/components/ui/toast";

describe("components/ui/toast", () => {
  it("uses the mounted shadcn toast store and provider", () => {
    expect(uiToast).toBe(shadcnToast);
    expect(UiToaster).toBe(ShadcnToaster);
  });
});
