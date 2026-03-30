import { http, HttpResponse } from "msw";
import { beforeEach, describe, vi } from "vitest";
import { render } from "vitest-browser-react";

import { MembershipsCard } from "@/components/users/profile/memberships-card";
import { reloadPage } from "@/lib/navigation";
import { API_BASE } from "@/testing/msw/handlers";
import { expect, test } from "@/testing/test-extend";

import { ProfileOrganizationsHarness } from "./profile-organizations.harness";

// ── Mocks ──

vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: vi.fn() }),
}));

vi.mock("@/auth.config", () => ({
  auth: vi.fn(),
}));

vi.mock("@/lib/navigation", () => ({
  reloadPage: vi.fn(),
}));

vi.mock("@/components/ui", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

// Server actions are NOT mocked — their fetch calls are intercepted by MSW
// (handlers in testing/msw/handlers.ts, auto-started via test-extend).

// ── Factories ──

function makeMembership(overrides: {
  id: string;
  role: string;
  tenantId: string;
}) {
  return {
    id: overrides.id,
    type: "memberships" as const,
    attributes: {
      role: overrides.role,
      date_joined: "2025-05-19T11:31:00Z",
    },
    relationships: {
      tenant: { data: { type: "tenants", id: overrides.tenantId } },
      user: { data: { type: "users", id: "user-1" } },
    },
  };
}

function makeTenant(id: string, name: string) {
  return {
    type: "tenants" as const,
    id,
    attributes: { name },
    relationships: { memberships: { meta: { count: 1 }, data: [] } },
  };
}

// ── UUID constants for submission tests (z.uuid() validation) ──

const UUID_T1 = "00000000-0000-4000-a000-000000000001";
const UUID_T2 = "00000000-0000-4000-a000-000000000002";

// ── Fixtures ──

const SINGLE_ORG = {
  memberships: [makeMembership({ id: "m1", role: "owner", tenantId: "t1" })],
  tenantsMap: { t1: makeTenant("t1", "Alpha Org") },
};

const TWO_ORGS = {
  memberships: [
    makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
    makeMembership({ id: "m2", role: "member", tenantId: "t2" }),
  ],
  tenantsMap: {
    t1: makeTenant("t1", "Alpha Org"),
    t2: makeTenant("t2", "Beta Org"),
  },
};

const THREE_ORGS = {
  memberships: [
    makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
    makeMembership({ id: "m2", role: "member", tenantId: "t2" }),
    makeMembership({ id: "m3", role: "admin", tenantId: "t3" }),
  ],
  tenantsMap: {
    t1: makeTenant("t1", "Alpha Org"),
    t2: makeTenant("t2", "Beta Org"),
    t3: makeTenant("t3", "Gamma Org"),
  },
};

const FIVE_ORGS = {
  memberships: [
    makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
    makeMembership({ id: "m2", role: "member", tenantId: "t2" }),
    makeMembership({ id: "m3", role: "admin", tenantId: "t3" }),
    makeMembership({ id: "m4", role: "member", tenantId: "t4" }),
    makeMembership({ id: "m5", role: "member", tenantId: "t5" }),
  ],
  tenantsMap: {
    t1: makeTenant("t1", "Alpha Org"),
    t2: makeTenant("t2", "Beta Org"),
    t3: makeTenant("t3", "Gamma Org"),
    t4: makeTenant("t4", "Delta Org"),
    t5: makeTenant("t5", "Epsilon Org"),
  },
};

const THREE_ORGS_ALL_OWNERS = {
  memberships: [
    makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
    makeMembership({ id: "m2", role: "owner", tenantId: "t2" }),
    makeMembership({ id: "m3", role: "owner", tenantId: "t3" }),
  ],
  tenantsMap: {
    t1: makeTenant("t1", "Alpha Org"),
    t2: makeTenant("t2", "Beta Org"),
    t3: makeTenant("t3", "Gamma Org"),
  },
};

const FIVE_ORGS_ALL_OWNERS = {
  memberships: [
    makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
    makeMembership({ id: "m2", role: "owner", tenantId: "t2" }),
    makeMembership({ id: "m3", role: "owner", tenantId: "t3" }),
    makeMembership({ id: "m4", role: "owner", tenantId: "t4" }),
    makeMembership({ id: "m5", role: "owner", tenantId: "t5" }),
  ],
  tenantsMap: {
    t1: makeTenant("t1", "Alpha Org"),
    t2: makeTenant("t2", "Beta Org"),
    t3: makeTenant("t3", "Gamma Org"),
    t4: makeTenant("t4", "Delta Org"),
    t5: makeTenant("t5", "Epsilon Org"),
  },
};

// ── UUID Fixtures (for form submission tests) ──

const TWO_ORGS_UUID = {
  memberships: [
    makeMembership({ id: "m1", role: "owner", tenantId: UUID_T1 }),
    makeMembership({ id: "m2", role: "member", tenantId: UUID_T2 }),
  ],
  tenantsMap: {
    [UUID_T1]: makeTenant(UUID_T1, "Alpha Org"),
    [UUID_T2]: makeTenant(UUID_T2, "Beta Org"),
  },
};

// ── Helper ──

function renderCard(props: {
  memberships: ReturnType<typeof makeMembership>[];
  tenantsMap: Record<string, ReturnType<typeof makeTenant>>;
  hasManageAccount?: boolean;
  sessionTenantId: string;
}) {
  return render(
    <MembershipsCard
      memberships={props.memberships}
      tenantsMap={props.tenantsMap}
      hasManageAccount={props.hasManageAccount ?? true}
      sessionTenantId={props.sessionTenantId}
    />,
  );
}

// ── Tests ──

describe("MembershipsCard", () => {
  beforeEach(() => {
    vi.stubGlobal("location.reload", vi.fn());
  });
  // ────────────────────────────────────────────
  // Card Structure & Rendering
  // ────────────────────────────────────────────

  describe("Card Structure & Rendering", () => {
    test("should show Organizations heading", async () => {
      const h = new ProfileOrganizationsHarness();
      renderCard({ ...SINGLE_ORG, sessionTenantId: "t1" });
      await expect.element(h.cardTitle()).toBeVisible();
    });

    test("should show 'No memberships found' message when empty", async () => {
      const h = new ProfileOrganizationsHarness();
      renderCard({
        memberships: [],
        tenantsMap: {},
        hasManageAccount: false,
        sessionTenantId: "t1",
      });
      await expect.element(h.noMembershipsMessage()).toBeVisible();
    });

    test("should render 1 row for 1 org", async () => {
      const h = new ProfileOrganizationsHarness();
      renderCard({ ...SINGLE_ORG, sessionTenantId: "t1" });
      await expect.element(h.orgName("Alpha Org")).toBeVisible();
    });

    test("should render 3 rows for 3 orgs", async () => {
      const h = new ProfileOrganizationsHarness();
      renderCard({ ...THREE_ORGS, sessionTenantId: "t1" });
      await expect.element(h.orgName("Alpha Org")).toBeVisible();
      await expect.element(h.orgName("Beta Org")).toBeVisible();
      await expect.element(h.orgName("Gamma Org")).toBeVisible();
    });

    test("should render without crash when tenant is missing from map", async () => {
      const h = new ProfileOrganizationsHarness();
      renderCard({
        memberships: [
          makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
        ],
        tenantsMap: {},
        hasManageAccount: false,
        sessionTenantId: "t1",
      });
      await expect.element(h.cardTitle()).toBeVisible();
    });

    test("should render special characters in org name correctly", async () => {
      const h = new ProfileOrganizationsHarness();
      const specialName = '<Test> & "Quotes"';
      renderCard({
        memberships: [
          makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
        ],
        tenantsMap: { t1: makeTenant("t1", specialName) },
        hasManageAccount: false,
        sessionTenantId: "other",
      });
      await expect.element(h.orgName(specialName)).toBeVisible();
    });

    test("should show Active badge on current org", async () => {
      const h = new ProfileOrganizationsHarness();
      renderCard({ ...SINGLE_ORG, sessionTenantId: "t1" });
      await expect.element(h.activeBadge()).toBeVisible();
    });
  });

  // ────────────────────────────────────────────
  // Create Organization
  // ────────────────────────────────────────────

  describe("Create Organization", () => {
    test("should show Create button regardless of hasManageAccount", async () => {
      const h = new ProfileOrganizationsHarness();
      renderCard({
        ...SINGLE_ORG,
        hasManageAccount: false,
        sessionTenantId: "t1",
      });
      await expect.element(h.createButton()).toBeVisible();
    });

    test("should show Create button when no memberships exist", async () => {
      const h = new ProfileOrganizationsHarness();
      renderCard({
        memberships: [],
        tenantsMap: {},
        hasManageAccount: false,
        sessionTenantId: "t1",
      });
      await expect.element(h.createButton()).toBeVisible();
    });
  });

  // ────────────────────────────────────────────
  // Switch Organization
  // ────────────────────────────────────────────

  describe("Switch Organization", () => {
    describe("Button visibility", () => {
      test("should not show Switch when only one org and it is active", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...SINGLE_ORG, sessionTenantId: "t1" });
        await expect.element(h.switchButtons().first()).not.toBeInTheDocument();
      });

      test("should show Switch on non-active org when owner", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...SINGLE_ORG, sessionTenantId: "other" });
        await expect.element(h.switchButtons().first()).toBeVisible();
      });

      test("should show Switch only on non-active orgs in multi-org", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });
        await expect.element(h.switchButtons().first()).toBeVisible();
        await expect.element(h.switchButtons().nth(1)).not.toBeInTheDocument();
      });

      test("should not show Switch for non-owner on single active org", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...SINGLE_ORG, sessionTenantId: "t1" });
        await expect.element(h.switchButtons().first()).not.toBeInTheDocument();
      });

      test("should show Switch on non-active orgs for non-owner", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });
        await expect.element(h.switchButtons().first()).toBeVisible();
      });
    });

    describe("Multi-org count", () => {
      test("should show 1 Switch button when 2 orgs and first is active", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });
        await expect.element(h.activeBadge()).toBeVisible();
        await expect.element(h.switchButtons().first()).toBeVisible();
        await expect.element(h.activeBadges().nth(1)).not.toBeInTheDocument();
        await expect.element(h.switchButtons().nth(1)).not.toBeInTheDocument();
      });

      test("should show Switch on first org when second is active", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t2" });
        await expect.element(h.activeBadge()).toBeVisible();
        await expect.element(h.switchButtons().first()).toBeVisible();
        await expect.element(h.orgName("Alpha Org")).toBeVisible();
        await expect.element(h.orgName("Beta Org")).toBeVisible();
      });

      test("should show 2 Switch buttons when middle org is active", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          hasManageAccount: false,
          sessionTenantId: "t2",
        });
        await expect.element(h.activeBadge()).toBeVisible();
        await expect.element(h.activeBadges().nth(1)).not.toBeInTheDocument();
        await expect.element(h.switchButtons().first()).toBeVisible();
        await expect.element(h.switchButtons().nth(1)).toBeVisible();
        await expect.element(h.switchButtons().nth(2)).not.toBeInTheDocument();
      });

      test("should show Switch on first two when last org is active", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          hasManageAccount: false,
          sessionTenantId: "t3",
        });
        await expect.element(h.activeBadge()).toBeVisible();
        await expect.element(h.switchButtons().first()).toBeVisible();
        await expect.element(h.switchButtons().nth(1)).toBeVisible();
        await expect.element(h.switchButtons().nth(2)).not.toBeInTheDocument();
      });

      test("should match Switch button count to non-active orgs", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          hasManageAccount: false,
          sessionTenantId: "t2",
        });
        // Beta active → Alpha and Gamma have Switch (2 buttons)
        await expect.element(h.switchButtons().first()).toBeVisible();
        await expect.element(h.switchButtons().nth(1)).toBeVisible();
        await expect.element(h.switchButtons().nth(2)).not.toBeInTheDocument();
      });

      test("should show 4 Switch buttons with 5 orgs and first active", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...FIVE_ORGS, sessionTenantId: "t1" });
        await expect.element(h.switchButtons().nth(0)).toBeVisible();
        await expect.element(h.switchButtons().nth(1)).toBeVisible();
        await expect.element(h.switchButtons().nth(2)).toBeVisible();
        await expect.element(h.switchButtons().nth(3)).toBeVisible();
        await expect.element(h.switchButtons().nth(4)).not.toBeInTheDocument();
        await expect.element(h.activeBadge()).toBeVisible();
        await expect.element(h.activeBadges().nth(1)).not.toBeInTheDocument();
      });
    });

    describe("Confirmation dialog", () => {
      test("should open confirmation dialog when clicking Switch", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });

        await h.clickSwitchOnFirstAvailable();

        await expect.element(h.dialog()).toBeVisible();
        await expect.element(h.confirmationTitle()).toBeVisible();
        await expect.element(h.confirmButton()).toBeVisible();
        await expect.element(h.cancelButton()).toBeVisible();
      });

      test("should close dialog without switching when clicking Cancel", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });

        await h.clickSwitchOnFirstAvailable();
        await expect.element(h.dialog()).toBeVisible();

        await h.cancelSwitch();

        await expect.element(h.dialog()).not.toBeInTheDocument();
        await expect.element(h.switchButtons().first()).toBeVisible();
      });

      test("should allow opening dialog for each non-active org", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          sessionTenantId: "t1",
        });

        await h.clickSwitchAt(0);
        await expect.element(h.dialog()).toBeVisible();
        await h.cancelSwitch();
        await expect.element(h.dialog()).not.toBeInTheDocument();

        await h.clickSwitchAt(1);
        await expect.element(h.dialog()).toBeVisible();
      });

      test("should carry the correct tenantId in dialog", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          sessionTenantId: "t1",
        });

        // Click switch on Beta (first Switch button)
        await h.clickSwitchAt(0);
        const input = h.hiddenTenantInput() as HTMLInputElement | null;
        expect(input?.value).toBe("t2");
        await h.cancelSwitch();

        // Click switch on Gamma (second Switch button)
        await h.clickSwitchAt(1);
        const input2 = h.hiddenTenantInput() as HTMLInputElement | null;
        expect(input2?.value).toBe("t3");
      });
    });

    describe("Modal isolation", () => {
      test("should target correct org when switching between org A and B", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          hasManageAccount: false,
          sessionTenantId: "t1",
        });

        await h.openSwitchModalAt(0);
        await expect.element(h.dialog()).toBeVisible();
        await h.cancelSwitch();

        await h.openSwitchModalAt(1);
        await expect.element(h.dialog()).toBeVisible();
      });
    });
  });

  // ────────────────────────────────────────────
  // Edit Organization
  // ────────────────────────────────────────────

  describe("Edit Organization", () => {
    describe("Button visibility", () => {
      test("should show Edit button when user is owner", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...SINGLE_ORG, sessionTenantId: "t1" });
        await expect.element(h.editButton()).toBeVisible();
      });

      test("should show Edit on all orgs when owner of all", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS_ALL_OWNERS,
          sessionTenantId: "t1",
        });
        await expect.element(h.editButtons().nth(0)).toBeVisible();
        await expect.element(h.editButtons().nth(1)).toBeVisible();
        await expect.element(h.editButtons().nth(2)).toBeVisible();
      });

      test("should only show Edit on owner memberships in mixed-role orgs", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          sessionTenantId: "t1",
        });
        // Only Alpha (owner) should show Edit
        await expect.element(h.editButtons().nth(0)).toBeVisible();
        await expect.element(h.editButtons().nth(1)).not.toBeInTheDocument();
      });

      test("should hide Edit button when user is not owner", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          hasManageAccount: false,
          sessionTenantId: "t1",
        });
        await expect.element(h.editButton()).not.toBeInTheDocument();
      });
    });

    describe("Modal content", () => {
      test("should display current org name in modal", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...SINGLE_ORG, sessionTenantId: "t1" });
        await h.openEditModal();

        await expect.element(h.dialog()).toBeVisible();
        await expect.element(h.currentNameDisplay("Alpha Org")).toBeVisible();
        await expect.element(h.editNameInput()).toBeVisible();
      });

      test("should show correct name when editing each org", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS_ALL_OWNERS,
          sessionTenantId: "t1",
        });

        await h.openEditModalAt(0);
        await expect.element(h.currentNameDisplay("Alpha Org")).toBeVisible();
        await h.cancel();

        await h.openEditModalAt(1);
        await expect.element(h.currentNameDisplay("Beta Org")).toBeVisible();
        await h.cancel();

        await h.openEditModalAt(2);
        await expect.element(h.currentNameDisplay("Gamma Org")).toBeVisible();
      });
    });

    describe("Modal isolation", () => {
      test("should show org B name after editing org A then B", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS_ALL_OWNERS,
          sessionTenantId: "t1",
        });

        await h.openEditModalAt(0);
        await expect.element(h.currentNameDisplay("Alpha Org")).toBeVisible();
        await h.cancel();

        await h.openEditModalAt(1);
        await expect.element(h.currentNameDisplay("Beta Org")).toBeVisible();
      });
    });
  });

  // ────────────────────────────────────────────
  // Delete Organization
  // ────────────────────────────────────────────

  describe("Delete Organization", () => {
    describe("Button visibility", () => {
      test("should not show Delete when only one org exists", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...SINGLE_ORG, sessionTenantId: "t1" });
        await expect.element(h.deleteButton()).not.toBeInTheDocument();
      });

      test("should show Delete when multiple orgs exist and user is owner", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });
        await expect.element(h.deleteButtons().first()).toBeVisible();
      });

      test("should show Delete on all orgs when owner of all", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS_ALL_OWNERS,
          sessionTenantId: "t1",
        });
        await expect.element(h.deleteButtons().nth(0)).toBeVisible();
        await expect.element(h.deleteButtons().nth(1)).toBeVisible();
        await expect.element(h.deleteButtons().nth(2)).toBeVisible();
      });

      test("should only show Delete on owner memberships in mixed-role orgs", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          sessionTenantId: "t2",
        });
        // Only Alpha (owner role) should show Delete
        await expect.element(h.deleteButtons().nth(0)).toBeVisible();
        await expect.element(h.deleteButtons().nth(1)).not.toBeInTheDocument();
      });

      test("should hide Delete on all orgs for non-owner", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          hasManageAccount: false,
          sessionTenantId: "t1",
        });
        await expect.element(h.deleteButton()).not.toBeInTheDocument();
      });
    });

    describe("Non-active tenant validation", () => {
      function renderForDeleteNonActive(tenantName = "Alpha Org") {
        const memberships = [
          makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
          makeMembership({ id: "m2", role: "member", tenantId: "t2" }),
        ];
        const tenantsMap = {
          t1: makeTenant("t1", tenantName),
          t2: makeTenant("t2", "Beta Org"),
        };
        // t2 is active → t1 is non-active, owner can delete it
        return renderCard({
          memberships,
          tenantsMap,
          sessionTenantId: "t2",
        });
      }

      test("should disable Delete button initially", async () => {
        const h = new ProfileOrganizationsHarness();
        renderForDeleteNonActive();
        await h.openDeleteModalAt(0);

        await expect.element(h.submitButton(/delete/i)).toBeDisabled();
      });

      test("should disable Delete with partial name match", async () => {
        const h = new ProfileOrganizationsHarness();
        renderForDeleteNonActive();
        await h.openDeleteModalAt(0);

        await h.fillDeleteConfirmation("Alpha Org", "Alpha");
        await expect.element(h.submitButton(/delete/i)).toBeDisabled();
      });

      test("should disable Delete with case mismatch", async () => {
        const h = new ProfileOrganizationsHarness();
        renderForDeleteNonActive();
        await h.openDeleteModalAt(0);

        await h.fillDeleteConfirmation("Alpha Org", "alpha org");
        await expect.element(h.submitButton(/delete/i)).toBeDisabled();
      });

      test("should enable Delete on exact name match", async () => {
        const h = new ProfileOrganizationsHarness();
        renderForDeleteNonActive();
        await h.openDeleteModalAt(0);

        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await expect.element(h.submitButton(/delete/i)).toBeEnabled();
      });

      test("should re-disable Delete when text is cleared", async () => {
        const h = new ProfileOrganizationsHarness();
        renderForDeleteNonActive();
        await h.openDeleteModalAt(0);

        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await expect.element(h.submitButton(/delete/i)).toBeEnabled();

        await h.fillDeleteConfirmation("Alpha Org", "");
        await expect.element(h.submitButton(/delete/i)).toBeDisabled();
      });

      test("should re-disable Delete when matched text is modified", async () => {
        const h = new ProfileOrganizationsHarness();
        renderForDeleteNonActive();
        await h.openDeleteModalAt(0);

        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await expect.element(h.submitButton(/delete/i)).toBeEnabled();

        await h.fillDeleteConfirmation("Alpha Org", "Alpha Orgx");
        await expect.element(h.submitButton(/delete/i)).toBeDisabled();
      });

      test("should not show target tenant select for non-active org", async () => {
        const h = new ProfileOrganizationsHarness();
        renderForDeleteNonActive();
        await h.openDeleteModalAt(0);

        await expect
          .element(h.switchToAfterDeletionText())
          .not.toBeInTheDocument();
        await expect.element(h.targetTenantSelect()).not.toBeInTheDocument();
      });

      test("should require exact match for special characters in name", async () => {
        const h = new ProfileOrganizationsHarness();
        const specialName = "O'Reilly & Co.";
        renderForDeleteNonActive(specialName);
        await h.openDeleteModalAt(0);

        await h.fillDeleteConfirmation(specialName, "OReilly Co");
        await expect.element(h.submitButton(/delete/i)).toBeDisabled();

        await h.fillDeleteConfirmation(specialName, specialName);
        await expect.element(h.submitButton(/delete/i)).toBeEnabled();
      });
    });

    describe("Active tenant — target selection", () => {
      test("should show target tenant select when deleting active org", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });
        // t1 is active (index 0) → delete opens with target select
        await h.openDeleteModalAt(0);

        await expect.element(h.switchToAfterDeletionText()).toBeVisible();
        await expect.element(h.targetTenantSelect()).toBeVisible();
      });

      test("should disable Delete even with correct name if no target selected", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });
        await h.openDeleteModalAt(0);

        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await expect.element(h.submitButton(/delete/i)).toBeDisabled();
      });

      test("should enable Delete when name matches and target is selected", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });
        await h.openDeleteModalAt(0);

        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await h.targetTenantSelect().click();
        await h.orgName("Beta Org").last().click();

        await expect.element(h.submitButton(/delete/i)).toBeEnabled();
      });

      test("should list only other orgs in target select, not self", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          sessionTenantId: "t1",
        });

        await h.openDeleteModalAt(0);
        await h.targetTenantSelect().click();

        await expect.element(h.orgName("Beta Org").last()).toBeVisible();
        await expect.element(h.orgName("Gamma Org").last()).toBeVisible();
      });

      test("should show 2 target options when deleting active in 3 orgs", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS,
          sessionTenantId: "t1",
        });

        await h.openDeleteModalAt(0);
        await h.targetTenantSelect().click();

        await expect.element(h.orgName("Beta Org").last()).toBeVisible();
        await expect.element(h.orgName("Gamma Org").last()).toBeVisible();
      });

      test("should show org names in target select, not IDs", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t1" });
        await h.openDeleteModalAt(0);
        await h.targetTenantSelect().click();

        await expect.element(h.orgName("Beta Org").last()).toBeVisible();
        await expect.element(h.orgName("t2")).not.toBeInTheDocument();
      });
    });

    describe("Edge cases", () => {
      test("should handle long org name in delete confirmation", async () => {
        const h = new ProfileOrganizationsHarness();
        const longName = "A".repeat(120);
        const memberships = [
          makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
          makeMembership({ id: "m2", role: "member", tenantId: "t2" }),
        ];
        const tenantsMap = {
          t1: makeTenant("t1", longName),
          t2: makeTenant("t2", "Beta Org"),
        };
        renderCard({
          memberships,
          tenantsMap,
          sessionTenantId: "t2",
        });

        await expect.element(h.orgName(longName)).toBeVisible();
        await h.openDeleteModalAt(0);
        await h.fillDeleteConfirmation(longName, longName);
        await expect.element(h.submitButton(/delete/i)).toBeEnabled();
      });

      test("should filter out self from available tenants correctly", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS_ALL_OWNERS,
          sessionTenantId: "t2",
        });

        // Open delete on Beta (active, index 1)
        await h.openDeleteModalAt(1);
        await h.targetTenantSelect().click();

        await expect.element(h.orgName("Alpha Org").last()).toBeVisible();
        await expect.element(h.orgName("Gamma Org").last()).toBeVisible();
      });

      test("should show Delete on all 5 orgs when owner of all", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...FIVE_ORGS_ALL_OWNERS,
          sessionTenantId: "t1",
        });
        await expect.element(h.deleteButtons().nth(4)).toBeVisible();
      });
    });

    describe("Modal isolation", () => {
      test("should show org B name after opening delete on A then B", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...THREE_ORGS_ALL_OWNERS,
          sessionTenantId: "t3",
        });

        await h.openDeleteModalAt(0);
        await expect.element(h.deleteConfirmInput("Alpha Org")).toBeVisible();
        await h.cancel();

        await h.openDeleteModalAt(1);
        await expect.element(h.deleteConfirmInput("Beta Org")).toBeVisible();
      });

      test("should reset input when reopening delete after cancel", async () => {
        const h = new ProfileOrganizationsHarness();
        renderCard({ ...TWO_ORGS, sessionTenantId: "t2" });

        await h.openDeleteModalAt(0);
        await h.fillDeleteConfirmation("Alpha Org", "Alpha");
        await h.cancel();

        await h.openDeleteModalAt(0);
        await expect.element(h.submitButton(/delete/i)).toBeDisabled();
      });
    });

    describe("Form submission", () => {
      test("should switch then delete when deleting the active tenant", async ({
        worker,
      }) => {
        const switchCalled: string[] = [];
        const deleteCalled: string[] = [];

        worker.use(
          http.post(`${API_BASE}/tokens/switch`, async ({ request }) => {
            const body = (await request.json()) as {
              data?: { attributes?: { tenant_id?: string } };
            };
            switchCalled.push(body?.data?.attributes?.tenant_id ?? "unknown");
            return HttpResponse.json({
              data: {
                attributes: {
                  access: "new-access-token",
                  refresh: "new-refresh-token",
                },
              },
            });
          }),
          http.delete(`${API_BASE}/tenants/:tenantId`, ({ params }) => {
            deleteCalled.push(params.tenantId as string);
            return new HttpResponse(null, { status: 204 });
          }),
        );

        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...TWO_ORGS_UUID,
          sessionTenantId: UUID_T1,
        });

        await h.openDeleteModalAt(0);
        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await h.selectTargetTenant("Beta Org");
        await expect.element(h.submitButton(/delete/i)).toBeEnabled();

        await h.submitDelete();

        // Wait for the async server action to complete
        await expect.poll(() => switchCalled.length).toBe(1);
        await expect.poll(() => deleteCalled.length).toBe(1);

        // Switch was called with the target tenant
        expect(switchCalled[0]).toBe(UUID_T2);
        // Delete was called with the tenant being deleted
        expect(deleteCalled[0]).toBe(UUID_T1);
        // Page should reload after successful switch+delete
        await expect
          .poll(() => vi.mocked(reloadPage).mock.calls.length)
          .toBeGreaterThanOrEqual(1);
      });

      test("should close modal after deleting a non-active tenant", async ({
        worker,
      }) => {
        const deleteCalled: string[] = [];

        worker.use(
          http.delete(`${API_BASE}/tenants/:tenantId`, ({ params }) => {
            deleteCalled.push(params.tenantId as string);
            return new HttpResponse(null, { status: 204 });
          }),
        );

        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...TWO_ORGS_UUID,
          sessionTenantId: UUID_T2,
        });

        // t1 is non-active → simple delete, no switch needed
        await h.openDeleteModalAt(0);
        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await expect.element(h.submitButton(/delete/i)).toBeEnabled();

        await h.submitDelete();

        await expect.poll(() => deleteCalled.length).toBe(1);
        expect(deleteCalled[0]).toBe(UUID_T1);

        // Modal should close after successful deletion
        await expect.element(h.dialog()).not.toBeInTheDocument();
      });

      test("should show error when switch fails during active tenant deletion", async ({
        worker,
      }) => {
        worker.use(
          http.post(`${API_BASE}/tokens/switch`, () => {
            return HttpResponse.json(
              { errors: [{ detail: "Unauthorized" }] },
              { status: 401 },
            );
          }),
        );

        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...TWO_ORGS_UUID,
          sessionTenantId: UUID_T1,
        });

        await h.openDeleteModalAt(0);
        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await h.selectTargetTenant("Beta Org");

        await h.submitDelete();

        // The submit button should re-enable after the error
        await expect.element(h.submitButton(/delete/i)).toBeEnabled();
        // Page should NOT reload on failure
        expect(vi.mocked(reloadPage)).not.toHaveBeenCalled();
      });

      test("should still switch when delete fails after successful switch", async ({
        worker,
      }) => {
        const switchCalled: string[] = [];

        worker.use(
          http.post(`${API_BASE}/tokens/switch`, async ({ request }) => {
            const body = (await request.json()) as {
              data?: { attributes?: { tenant_id?: string } };
            };
            switchCalled.push(body?.data?.attributes?.tenant_id ?? "unknown");
            return HttpResponse.json({
              data: {
                attributes: {
                  access: "new-access-token",
                  refresh: "new-refresh-token",
                },
              },
            });
          }),
          http.delete(`${API_BASE}/tenants/:tenantId`, () => {
            return HttpResponse.json(
              { errors: [{ detail: "Internal server error" }] },
              { status: 500 },
            );
          }),
        );

        const h = new ProfileOrganizationsHarness();
        renderCard({
          ...TWO_ORGS_UUID,
          sessionTenantId: UUID_T1,
        });

        await h.openDeleteModalAt(0);
        await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
        await h.selectTargetTenant("Beta Org");

        await h.submitDelete();

        // Switch should have been called even though delete will fail
        await expect.poll(() => switchCalled.length).toBe(1);
        expect(switchCalled[0]).toBe(UUID_T2);
        // Page should still reload because switch succeeded (session was updated)
        await expect
          .poll(() => vi.mocked(reloadPage).mock.calls.length)
          .toBeGreaterThanOrEqual(1);
      });
    });
  });
});
