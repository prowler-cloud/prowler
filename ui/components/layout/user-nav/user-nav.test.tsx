import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TooltipProvider } from "@/components/shadcn/tooltip";

import { UserNav } from "./user-nav";

vi.mock("next-auth/react", () => ({
  useSession: () => ({ data: { user: { name: "Jane Doe" } } }),
}));

vi.mock("@/actions/auth", () => ({ logOut: vi.fn() }));

describe("UserNav", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the initials without requesting an avatar image", () => {
    // Given
    const imageSpy = vi.spyOn(window, "Image");

    // When
    render(
      <TooltipProvider>
        <UserNav />
      </TooltipProvider>,
    );

    // Then
    expect(screen.getByText("JD")).toBeInTheDocument();
    expect(imageSpy).not.toHaveBeenCalled();
  });
});
