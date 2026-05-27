import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { refreshMock, updateScanMock, toastMock } = vi.hoisted(() => ({
  refreshMock: vi.fn(),
  updateScanMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

vi.mock("@/actions/scans", () => ({
  updateScan: updateScanMock,
}));

vi.mock("@/components/ui/toast", () => ({
  toast: toastMock,
}));

vi.mock("@/components/shadcn/modal", () => ({
  Modal: ({
    children,
    open,
    title,
  }: {
    children: React.ReactNode;
    open: boolean;
    title: string;
  }) =>
    open ? (
      <div role="dialog" aria-label={title}>
        {children}
      </div>
    ) : null,
}));

import { EditAliasModal } from "./edit-alias-modal";

describe("EditAliasModal", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    updateScanMock.mockResolvedValue({});
  });

  it("seeds the input with the current alias", () => {
    render(
      <EditAliasModal
        open
        onOpenChange={vi.fn()}
        scanId="scan-1"
        currentAlias="Production audit"
      />,
    );

    expect(screen.getByLabelText("Alias")).toHaveValue("Production audit");
  });

  it("rejects an unchanged alias before calling the action", async () => {
    const user = userEvent.setup();

    render(
      <EditAliasModal
        open
        onOpenChange={vi.fn()}
        scanId="scan-1"
        currentAlias="Production audit"
      />,
    );

    await user.click(screen.getByRole("button", { name: /save/i }));

    expect(
      await screen.findByText(
        /new alias must be different from the current one/i,
      ),
    ).toBeInTheDocument();
    expect(updateScanMock).not.toHaveBeenCalled();
  });

  it("rejects a whitespace-only edit of the current alias", async () => {
    const user = userEvent.setup();

    render(
      <EditAliasModal
        open
        onOpenChange={vi.fn()}
        scanId="scan-1"
        currentAlias="Production audit"
      />,
    );

    const input = screen.getByLabelText("Alias");
    await user.type(input, "   ");
    await user.click(screen.getByRole("button", { name: /save/i }));

    expect(
      await screen.findByText(
        /new alias must be different from the current one/i,
      ),
    ).toBeInTheDocument();
    expect(updateScanMock).not.toHaveBeenCalled();
  });

  it("submits the new alias as scanName", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();

    render(
      <EditAliasModal
        open
        onOpenChange={onOpenChange}
        scanId="scan-1"
        currentAlias="Old name"
      />,
    );

    const input = screen.getByLabelText("Alias");
    await user.clear(input);
    await user.type(input, "Brand new name");
    await user.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => expect(updateScanMock).toHaveBeenCalled());

    const formData = updateScanMock.mock.calls[0][0] as FormData;
    expect(formData.get("scanId")).toBe("scan-1");
    expect(formData.get("scanName")).toBe("Brand new name");
    expect(toastMock).toHaveBeenCalled();
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("accepts aliases up to the API limit of 100 characters", async () => {
    const user = userEvent.setup();
    const alias = "a".repeat(100);

    render(
      <EditAliasModal
        open
        onOpenChange={vi.fn()}
        scanId="scan-1"
        currentAlias="Old name"
      />,
    );

    const input = screen.getByLabelText("Alias");
    await user.clear(input);
    await user.type(input, alias);
    await user.click(screen.getByRole("button", { name: /save/i }));

    await waitFor(() => expect(updateScanMock).toHaveBeenCalled());

    const formData = updateScanMock.mock.calls[0][0] as FormData;
    expect(formData.get("scanName")).toBe(alias);
  });

  it("rejects aliases over the API limit of 100 characters", async () => {
    const user = userEvent.setup();

    render(
      <EditAliasModal
        open
        onOpenChange={vi.fn()}
        scanId="scan-1"
        currentAlias="Old name"
      />,
    );

    const input = screen.getByLabelText("Alias");
    await user.clear(input);
    await user.type(input, "a".repeat(101));
    await user.click(screen.getByRole("button", { name: /save/i }));

    expect(
      await screen.findByText(/alias must not exceed 100 characters/i),
    ).toBeInTheDocument();
    expect(updateScanMock).not.toHaveBeenCalled();
  });

  it("surfaces server-side errors on the alias field", async () => {
    const user = userEvent.setup();
    updateScanMock.mockResolvedValueOnce({
      errors: [{ detail: "Alias already in use" }],
    });

    render(
      <EditAliasModal
        open
        onOpenChange={vi.fn()}
        scanId="scan-1"
        currentAlias="Old name"
      />,
    );

    const input = screen.getByLabelText("Alias");
    await user.clear(input);
    await user.type(input, "Conflicting");
    await user.click(screen.getByRole("button", { name: /save/i }));

    expect(await screen.findByText("Alias already in use")).toBeInTheDocument();
  });
});
