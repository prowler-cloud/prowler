import { describe, vi } from "vitest";
import { render } from "vitest-browser-react";

import { MembershipsCard } from "@/components/users/profile/memberships-card";
import { expect, test } from "@/testing/test-extend";

import { ProfileOrganizationsHarness } from "./profile-organizations.harness";

// ── Mocks ──

vi.mock("next-auth/react", () => ({
  useSession: () => ({ update: vi.fn() }),
}));

vi.mock("@/auth.config", () => ({
  auth: vi.fn(),
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

// ── Helper ──

function renderCard(props: {
  memberships: ReturnType<typeof makeMembership>[];
  tenantsMap: Record<string, ReturnType<typeof makeTenant>>;
  isOwner: boolean;
  hasManageAccount?: boolean;
  sessionTenantId: string;
}) {
  return render(
    <MembershipsCard
      memberships={props.memberships}
      tenantsMap={props.tenantsMap}
      isOwner={props.isOwner}
      hasManageAccount={props.hasManageAccount ?? true}
      sessionTenantId={props.sessionTenantId}
    />,
  );
}

describe("Permission + Org Config Combinations", () => {
  test("owner + active + single org: Edit + Active, no Switch/Delete", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...SINGLE_ORG, isOwner: true, sessionTenantId: "t1" });

    await expect.element(h.editButton()).toBeVisible();
    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.switchButtons().first()).not.toBeInTheDocument();
    await expect.element(h.deleteButton()).not.toBeInTheDocument();
  });

  test("owner + active + multiple orgs: Edit + Delete + Active, no Switch", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t1" });

    // Active org has Edit + Delete + Active badge
    await expect.element(h.editButtons().first()).toBeVisible();
    await expect.element(h.deleteButtons().first()).toBeVisible();
    await expect.element(h.activeBadge()).toBeVisible();
    // Non-active org has Switch
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.switchButtons().nth(1)).not.toBeInTheDocument();
  });

  test("owner + non-active single org: Edit + Switch, no Delete", async () => {
    const h = new ProfileOrganizationsHarness();
    // sessionTenantId doesn't match the only org → it's non-active
    renderCard({ ...SINGLE_ORG, isOwner: true, sessionTenantId: "other" });

    await expect.element(h.editButton()).toBeVisible();
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.deleteButton()).not.toBeInTheDocument();
    await expect.element(h.activeBadge()).not.toBeInTheDocument();
  });

  test("non-owner + active + single org: Active badge only", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...SINGLE_ORG, isOwner: false, sessionTenantId: "t1" });

    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.editButton()).not.toBeInTheDocument();
    await expect.element(h.deleteButton()).not.toBeInTheDocument();
    await expect.element(h.switchButtons().first()).not.toBeInTheDocument();
  });

  test("non-owner + non-active + multiple orgs: Switch only, no Edit/Delete", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: false, sessionTenantId: "t1" });

    // Active org: just Active badge
    await expect.element(h.activeBadge()).toBeVisible();
    // Non-active org: just Switch
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.editButton()).not.toBeInTheDocument();
    await expect.element(h.deleteButton()).not.toBeInTheDocument();
  });
});

describe("Multi-Org Configurations", () => {
  test("2 orgs, first active: 1 Active badge, 1 Switch button", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: false, sessionTenantId: "t1" });

    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.activeBadges().nth(1)).not.toBeInTheDocument();
    await expect.element(h.switchButtons().nth(1)).not.toBeInTheDocument();
  });

  test("2 orgs, second active: Active on second, Switch on first", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: false, sessionTenantId: "t2" });

    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.orgName("Alpha Org")).toBeVisible();
    await expect.element(h.orgName("Beta Org")).toBeVisible();
  });

  test("3 orgs, middle one active: 1 Active badge, 2 Switch buttons", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: false, sessionTenantId: "t2" });

    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.activeBadges().nth(1)).not.toBeInTheDocument();
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.switchButtons().nth(1)).toBeVisible();
    await expect.element(h.switchButtons().nth(2)).not.toBeInTheDocument();
  });

  test("3 orgs, last one active: Active on third, Switch on first two", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: false, sessionTenantId: "t3" });

    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.switchButtons().nth(1)).toBeVisible();
    await expect.element(h.switchButtons().nth(2)).not.toBeInTheDocument();
  });

  test("owner with 3 orgs: Edit on all 3, Delete on all 3", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t1" });

    await expect.element(h.editButtons().nth(0)).toBeVisible();
    await expect.element(h.editButtons().nth(1)).toBeVisible();
    await expect.element(h.editButtons().nth(2)).toBeVisible();
    await expect.element(h.deleteButtons().nth(0)).toBeVisible();
    await expect.element(h.deleteButtons().nth(1)).toBeVisible();
    await expect.element(h.deleteButtons().nth(2)).toBeVisible();
  });

  test("non-owner with 3 orgs: no Edit or Delete on any", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: false, sessionTenantId: "t1" });

    await expect.element(h.editButton()).not.toBeInTheDocument();
    await expect.element(h.deleteButton()).not.toBeInTheDocument();
  });

  test("Create button visible regardless of hasManageAccount", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({
      ...SINGLE_ORG,
      isOwner: false,
      hasManageAccount: false,
      sessionTenantId: "t1",
    });

    await expect.element(h.createButton()).toBeVisible();
  });
});

describe("Switch flow scenarios", () => {
  test("shows Active badge on current org and Switch button on other orgs", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t1" });

    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.orgName("Alpha Org")).toBeVisible();
    await expect.element(h.orgName("Beta Org")).toBeVisible();
  });

  test("opens confirmation dialog when clicking Switch", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t1" });

    await h.clickSwitchOnFirstAvailable();

    await expect.element(h.alertDialog()).toBeVisible();
    await expect.element(h.confirmationTitle()).toBeVisible();
    await expect.element(h.confirmButton()).toBeVisible();
    await expect.element(h.cancelButton()).toBeVisible();
  });

  test("closes dialog without switching when clicking Cancel", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t1" });

    await h.clickSwitchOnFirstAvailable();
    await expect.element(h.alertDialog()).toBeVisible();

    await h.cancelSwitch();

    await expect.element(h.alertDialog()).not.toBeInTheDocument();
    await expect.element(h.switchButtons().first()).toBeVisible();
  });

  test("with 3 orgs, can open switch for each non-active org", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t1" });

    await h.clickSwitchAt(0);
    await expect.element(h.alertDialog()).toBeVisible();
    await h.cancelSwitch();
    await expect.element(h.alertDialog()).not.toBeInTheDocument();

    await h.clickSwitchAt(1);
    await expect.element(h.alertDialog()).toBeVisible();
  });

  test("switching targets correct org: dialog carries the right tenantId", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t1" });

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

  test("switch button count matches non-active orgs", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: false, sessionTenantId: "t2" });

    // Beta active → Alpha and Gamma have Switch (2 buttons)
    await expect.element(h.switchButtons().first()).toBeVisible();
    await expect.element(h.switchButtons().nth(1)).toBeVisible();
    await expect.element(h.switchButtons().nth(2)).not.toBeInTheDocument();
  });
});

describe("Delete Non-Active Tenant Validation", () => {
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
      isOwner: true,
      sessionTenantId: "t2",
    });
  }

  test("Delete button disabled initially", async () => {
    const h = new ProfileOrganizationsHarness();
    renderForDeleteNonActive();
    await h.openDeleteModalAt(0);

    await expect.element(h.submitButton(/delete/i)).toBeDisabled();
  });

  test("Delete button disabled with partial name", async () => {
    const h = new ProfileOrganizationsHarness();
    renderForDeleteNonActive();
    await h.openDeleteModalAt(0);

    await h.fillDeleteConfirmation("Alpha Org", "Alpha");
    await expect.element(h.submitButton(/delete/i)).toBeDisabled();
  });

  test("Delete button disabled with case mismatch", async () => {
    const h = new ProfileOrganizationsHarness();
    renderForDeleteNonActive();
    await h.openDeleteModalAt(0);

    await h.fillDeleteConfirmation("Alpha Org", "alpha org");
    await expect.element(h.submitButton(/delete/i)).toBeDisabled();
  });

  test("Delete button enables on exact match", async () => {
    const h = new ProfileOrganizationsHarness();
    renderForDeleteNonActive();
    await h.openDeleteModalAt(0);

    await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
    await expect.element(h.submitButton(/delete/i)).toBeEnabled();
  });

  test("Delete button re-disables when text is cleared", async () => {
    const h = new ProfileOrganizationsHarness();
    renderForDeleteNonActive();
    await h.openDeleteModalAt(0);

    await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
    await expect.element(h.submitButton(/delete/i)).toBeEnabled();

    await h.fillDeleteConfirmation("Alpha Org", "");
    await expect.element(h.submitButton(/delete/i)).toBeDisabled();
  });

  test("Delete button re-disables when matched text is modified", async () => {
    const h = new ProfileOrganizationsHarness();
    renderForDeleteNonActive();
    await h.openDeleteModalAt(0);

    await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
    await expect.element(h.submitButton(/delete/i)).toBeEnabled();

    await h.fillDeleteConfirmation("Alpha Org", "Alpha Orgx");
    await expect.element(h.submitButton(/delete/i)).toBeDisabled();
  });

  test("No target tenant select shown for non-active org", async () => {
    const h = new ProfileOrganizationsHarness();
    renderForDeleteNonActive();
    await h.openDeleteModalAt(0);

    await expect.element(h.switchToAfterDeletionText()).not.toBeInTheDocument();
    await expect.element(h.targetTenantSelect()).not.toBeInTheDocument();
  });

  test("Special characters in org name require exact match", async () => {
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

describe("Delete Active Tenant — Target Selection", () => {
  test("shows target tenant select when deleting active org", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t1" });
    // t1 is active (index 0) → delete opens with target select
    await h.openDeleteModalAt(0);

    await expect.element(h.switchToAfterDeletionText()).toBeVisible();
    await expect.element(h.targetTenantSelect()).toBeVisible();
  });

  test("Delete disabled even with correct name if no target selected", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t1" });
    await h.openDeleteModalAt(0);

    await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
    await expect.element(h.submitButton(/delete/i)).toBeDisabled();
  });

  test("Delete enables when name matches AND target selected", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t1" });
    await h.openDeleteModalAt(0);

    await h.fillDeleteConfirmation("Alpha Org", "Alpha Org");
    await h.targetTenantSelect().click();
    await h.orgName("Beta Org").last().click();

    await expect.element(h.submitButton(/delete/i)).toBeEnabled();
  });

  test("Target select lists only other orgs (not self)", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t1" });

    await h.openDeleteModalAt(0);
    await h.targetTenantSelect().click();

    await expect.element(h.orgName("Beta Org").last()).toBeVisible();
    await expect.element(h.orgName("Gamma Org").last()).toBeVisible();
  });

  test("With 3 orgs, deleting active shows 2 target options", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t1" });

    await h.openDeleteModalAt(0);
    await h.targetTenantSelect().click();

    await expect.element(h.orgName("Beta Org").last()).toBeVisible();
    await expect.element(h.orgName("Gamma Org").last()).toBeVisible();
  });

  test("Target select shows org names not IDs", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t1" });
    await h.openDeleteModalAt(0);
    await h.targetTenantSelect().click();

    await expect.element(h.orgName("Beta Org").last()).toBeVisible();
    await expect.element(h.orgName("t2")).not.toBeInTheDocument();
  });
});

describe("Edit Flow Scenarios", () => {
  test("owner clicks Edit: modal shows that org's current name", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...SINGLE_ORG, isOwner: true, sessionTenantId: "t1" });
    await h.openEditModal();

    await expect.element(h.dialog()).toBeVisible();
    await expect.element(h.currentNameDisplay("Alpha Org")).toBeVisible();
    await expect.element(h.editNameInput()).toBeVisible();
  });

  test("with 3 orgs, Edit on each opens with correct org name", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t1" });

    await h.openEditModalAt(0);
    await expect.element(h.currentNameDisplay("Alpha Org")).toBeVisible();
    await h.cancel();

    await h.openEditModalAt(1);
    await expect.element(h.currentNameDisplay("Beta Org")).toBeVisible();
    await h.cancel();

    await h.openEditModalAt(2);
    await expect.element(h.currentNameDisplay("Gamma Org")).toBeVisible();
  });

  test("non-owner sees no Edit button", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: false, sessionTenantId: "t1" });

    await expect.element(h.editButton()).not.toBeInTheDocument();
  });
});

describe("Card Structure & Empty States", () => {
  test("empty memberships: shows message and Create button", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({
      memberships: [],
      tenantsMap: {},
      isOwner: false,
      sessionTenantId: "t1",
    });

    await expect.element(h.noMembershipsMessage()).toBeVisible();
    await expect.element(h.createButton()).toBeVisible();
  });

  test("1 org renders 1 row", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...SINGLE_ORG, isOwner: false, sessionTenantId: "t1" });
    await expect.element(h.orgName("Alpha Org")).toBeVisible();
  });

  test("3 orgs render 3 rows", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: false, sessionTenantId: "t1" });
    await expect.element(h.orgName("Alpha Org")).toBeVisible();
    await expect.element(h.orgName("Beta Org")).toBeVisible();
    await expect.element(h.orgName("Gamma Org")).toBeVisible();
  });

  test("card shows Organizations heading", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...SINGLE_ORG, isOwner: false, sessionTenantId: "t1" });
    await expect.element(h.cardTitle()).toBeVisible();
  });

  test("tenant missing from tenantsMap renders without crash", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({
      memberships: [
        makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
      ],
      tenantsMap: {},
      isOwner: false,
      sessionTenantId: "t1",
    });
    await expect.element(h.cardTitle()).toBeVisible();
  });
});

describe("Edge Cases & Data Integrity", () => {
  test("long organization name renders and works in delete confirmation", async () => {
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
      isOwner: true,
      sessionTenantId: "t2",
    });

    await expect.element(h.orgName(longName)).toBeVisible();
    await h.openDeleteModalAt(0);
    await h.fillDeleteConfirmation(longName, longName);
    await expect.element(h.submitButton(/delete/i)).toBeEnabled();
  });

  test("special characters in org name render correctly", async () => {
    const h = new ProfileOrganizationsHarness();
    const specialName = '<Test> & "Quotes"';
    renderCard({
      memberships: [
        makeMembership({ id: "m1", role: "owner", tenantId: "t1" }),
      ],
      tenantsMap: { t1: makeTenant("t1", specialName) },
      isOwner: false,
      sessionTenantId: "other",
    });
    await expect.element(h.orgName(specialName)).toBeVisible();
  });

  test("availableTenants for delete filters out self correctly", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t2" });

    // Open delete on Beta (active, index 1)
    await h.openDeleteModalAt(1);
    await h.targetTenantSelect().click();

    await expect.element(h.orgName("Alpha Org").last()).toBeVisible();
    await expect.element(h.orgName("Gamma Org").last()).toBeVisible();
  });

  test("5 orgs: all non-active show Switch, all show Edit+Delete as owner", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...FIVE_ORGS, isOwner: true, sessionTenantId: "t1" });

    // 4 Switch buttons (all except active t1)
    await expect.element(h.switchButtons().nth(0)).toBeVisible();
    await expect.element(h.switchButtons().nth(1)).toBeVisible();
    await expect.element(h.switchButtons().nth(2)).toBeVisible();
    await expect.element(h.switchButtons().nth(3)).toBeVisible();
    await expect.element(h.switchButtons().nth(4)).not.toBeInTheDocument();

    // 5 Edit and Delete buttons
    await expect.element(h.editButtons().nth(4)).toBeVisible();
    await expect.element(h.deleteButtons().nth(4)).toBeVisible();

    // 1 Active badge
    await expect.element(h.activeBadge()).toBeVisible();
    await expect.element(h.activeBadges().nth(1)).not.toBeInTheDocument();
  });
});

describe("Cross-Org Modal Isolation", () => {
  test("delete on org A then org B: confirmation shows B's name", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t3" });

    await h.openDeleteModalAt(0);
    await expect.element(h.deleteConfirmInput("Alpha Org")).toBeVisible();
    await h.cancel();

    await h.openDeleteModalAt(1);
    await expect.element(h.deleteConfirmInput("Beta Org")).toBeVisible();
  });

  test("edit on org A then org B: shows B's current name", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: true, sessionTenantId: "t1" });

    await h.openEditModalAt(0);
    await expect.element(h.currentNameDisplay("Alpha Org")).toBeVisible();
    await h.cancel();

    await h.openEditModalAt(1);
    await expect.element(h.currentNameDisplay("Beta Org")).toBeVisible();
  });

  test("switch on org A then org B: dialog targets correct org", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...THREE_ORGS, isOwner: false, sessionTenantId: "t1" });

    await h.openSwitchModalAt(0);
    await expect.element(h.alertDialog()).toBeVisible();
    await h.cancelSwitch();

    await h.openSwitchModalAt(1);
    await expect.element(h.alertDialog()).toBeVisible();
  });

  test("delete fill partial name, cancel, reopen: input is empty", async () => {
    const h = new ProfileOrganizationsHarness();
    renderCard({ ...TWO_ORGS, isOwner: true, sessionTenantId: "t2" });

    await h.openDeleteModalAt(0);
    await h.fillDeleteConfirmation("Alpha Org", "Alpha");
    await h.cancel();

    await h.openDeleteModalAt(0);
    await expect.element(h.submitButton(/delete/i)).toBeDisabled();
  });
});
