import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/actions/realtime", () => ({
  deleteRealtimeCredential: vi.fn(),
  saveRealtimeCredential: vi.fn(),
}));
vi.mock("@/components/shadcn/toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));
vi.mock("@/components/realtime/remediation-list", () => ({
  RemediationList: ({ providerId }: { providerId?: string }) => (
    <div>remediation list for {providerId}</div>
  ),
}));
vi.mock("@/components/realtime/template-guide", () => ({
  TemplateGuide: () => <div>template guide</div>,
}));

import { CredentialsForm } from "./credentials-form";

describe("CredentialsForm", () => {
  it("lists what the permission allows, with the template that creates it", () => {
    render(
      <CredentialsForm
        providerId="p1"
        credential={null}
        canManage
        onChanged={vi.fn()}
      />,
    );

    expect(screen.getByText("Credentials for remediation only")).toBeVisible();
    expect(screen.getByText("remediation list for p1")).toBeVisible();
    expect(screen.getByText("template guide")).toBeVisible();
  });
});
