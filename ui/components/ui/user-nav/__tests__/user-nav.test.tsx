import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getOrderedFlows } from "@/lib/onboarding";

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

// Opens the avatar menu and expands the "Product tour" submenu. Radix renders
// sub-content items only once the sub-trigger is opened, and in jsdom the
// reliable open path is keyboard navigation (focus the trigger, ArrowRight),
// which also exercises the accessible keyboard interaction.
const openProductTourSubmenu = async (
  user: ReturnType<typeof userEvent.setup>,
) => {
  await user.click(screen.getByRole("button", { name: /account menu/i }));
  const productTour = await screen.findByRole("menuitem", {
    name: /product tour/i,
  });
  productTour.focus();
  await user.keyboard("{ArrowRight}");
  return productTour;
};

describe("UserNav", () => {
  beforeEach(() => {
    pushMock.mockClear();
    logOutMock.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when the avatar menu is opened", () => {
    it("renders a product tour entry that is always present", async () => {
      // Given - an authenticated user
      const user = userEvent.setup();
      render(<UserNav />);

      // When - the user opens the avatar menu
      await user.click(screen.getByRole("button", { name: /account menu/i }));

      // Then - the product tour entry is offered regardless of state
      expect(
        await screen.findByRole("menuitem", { name: /product tour/i }),
      ).toBeInTheDocument();
    });

    it("lists every ordered onboarding flow inside the product tour submenu", async () => {
      // Given - the registry exposes the ordered flows
      const flows = getOrderedFlows();
      const user = userEvent.setup();
      render(<UserNav />);

      // When - the user opens the product tour submenu
      await openProductTourSubmenu(user);

      // Then - one entry per ordered flow is offered, labelled by flow title
      for (const flow of flows) {
        expect(
          await screen.findByRole("menuitem", { name: flow.title }),
        ).toBeInTheDocument();
      }
    });

    it("replays the selected single flow via the onboarding query param", async () => {
      // Given - the product tour submenu is open
      const flows = getOrderedFlows();
      const targetIndex = 2; // a non-first flow proves the list is not hardcoded
      const target = flows[targetIndex];
      const user = userEvent.setup();
      render(<UserNav />);
      await openProductTourSubmenu(user);
      await screen.findByRole("menuitem", { name: target.title });

      // When - the user moves to that flow's entry and activates it
      for (let step = 0; step < targetIndex; step += 1) {
        await user.keyboard("{ArrowDown}");
      }
      await user.keyboard("{Enter}");

      // Then - the app navigates to that single flow's replay URL only
      expect(pushMock).toHaveBeenCalledWith(
        `${target.route}?onboarding=${target.id}`,
      );
    });

    it("navigates to the first flow's replay URL when its entry is selected", async () => {
      // Given - the product tour submenu is open
      const [firstFlow] = getOrderedFlows();
      const user = userEvent.setup();
      render(<UserNav />);
      await openProductTourSubmenu(user);
      await screen.findByRole("menuitem", { name: firstFlow.title });

      // When - the user activates the first (focused) flow entry
      await user.keyboard("{Enter}");

      // Then - the first flow replays through the URL transport
      expect(pushMock).toHaveBeenCalledWith(
        `${firstFlow.route}?onboarding=${firstFlow.id}`,
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
