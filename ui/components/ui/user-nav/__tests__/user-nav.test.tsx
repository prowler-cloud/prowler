import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { UserNav } from "../user-nav";

const pushMock = vi.fn();
const logOutMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, replace: vi.fn() }),
}));

vi.mock("next-auth/react", () => ({
  useSession: () => ({ data: { user: { name: "Ada Lovelace" } } }),
}));

vi.mock("@/auth.config", () => ({
  signIn: vi.fn(),
  signOut: vi.fn(),
}));

vi.mock("@/actions/auth", () => ({
  logOut: () => logOutMock(),
}));

describe("UserNav", () => {
  beforeEach(() => {
    pushMock.mockClear();
    logOutMock.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when the avatar menu is opened", () => {
    it("renders a restart onboarding entry that is always present", async () => {
      // Given - an authenticated user
      const user = userEvent.setup();
      render(<UserNav />);

      // When - the user opens the avatar menu
      await user.click(screen.getByRole("button", { name: /account menu/i }));

      // Then - the restart-onboarding entry is offered regardless of state
      expect(
        await screen.findByRole("menuitem", { name: /product tour/i }),
      ).toBeInTheDocument();
    });

    it("navigates to the first flow's route with the onboarding query param", async () => {
      // Given - the avatar menu is open
      const user = userEvent.setup();
      render(<UserNav />);
      await user.click(screen.getByRole("button", { name: /account menu/i }));
      const productTour = await screen.findByRole("menuitem", {
        name: /product tour/i,
      });

      // When - the user activates the restart entry
      await user.click(productTour);

      // Then - the app hands off to the first flow via the URL transport
      expect(pushMock).toHaveBeenCalledWith(
        "/providers?onboarding=add-provider",
      );
    });

    it("preserves the existing account settings and sign out entries", async () => {
      // Given - the avatar menu is open
      const user = userEvent.setup();
      render(<UserNav />);
      await user.click(screen.getByRole("button", { name: /account menu/i }));

      // Then - the account settings link keeps its destination
      const accountSettings = await screen.findByRole("menuitem", {
        name: /account settings/i,
      });
      expect(accountSettings).toHaveAttribute("href", "/profile");

      // When - the user signs out
      await user.click(
        await screen.findByRole("menuitem", { name: /sign out/i }),
      );

      // Then - the existing sign-out action still fires
      await waitFor(() => expect(logOutMock).toHaveBeenCalledTimes(1));
    });
  });
});
