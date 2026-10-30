import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getRemediations } = vi.hoisted(() => ({ getRemediations: vi.fn() }));

vi.mock("@/actions/realtime", () => ({
  getRealtimeRemediations: getRemediations,
}));

import type { RealtimeRemediation } from "@/types/realtime";

import { RemediationList } from "./remediation-list";

const PROVIDER = "0b8c2b46-7f3a-4d1e-9a52-3f5f1d6a7c10";

const sg: RealtimeRemediation = {
  id: "security-group-ingress",
  title: "Close open security group rules",
  effect: "Removes the rule that opens a sensitive port to the internet.",
  checks: ["ec2_sg_ssh_open", "ec2_sg_rdp_open"],
  active_checks: ["ec2_sg_ssh_open"],
  iam_actions: ["ec2:RevokeSecurityGroupIngress", "ec2:DescribeSecurityGroups"],
  revertible: true,
  undo: "Adds the same rule back.",
  in_enforced_scope: true,
};

const s3: RealtimeRemediation = {
  id: "s3-public-access",
  title: "Block public access on a bucket",
  effect: "Turns on the bucket public access block.",
  checks: ["s3_public"],
  active_checks: [],
  iam_actions: ["s3:PutBucketPublicAccessBlock"],
  revertible: false,
  undo: "Cannot be restored automatically.",
  in_enforced_scope: false,
};

describe("RemediationList", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getRemediations.mockResolvedValue({ ok: true, data: [sg, s3] });
  });

  it("is titled as what the permission allows, and nothing more", async () => {
    render(<RemediationList providerId={PROVIDER} />);

    expect(
      await screen.findByRole("heading", {
        name: "With this permission Prowler will only be able to:",
      }),
    ).toBeVisible();
    expect(getRemediations).toHaveBeenCalledWith(PROVIDER);
    expect(
      screen.getByText(/Nothing outside this list is ever fixed automatically/),
    ).toBeVisible();
    expect(
      screen.getByText(/only on the resource named in the event/),
    ).toBeVisible();
    expect(screen.getByText(/dry run on/i)).toBeVisible();
    expect(screen.getByText(/Every fix is audited/)).toBeVisible();
  });

  it("lists each fix with its effect, checks and undo text", async () => {
    render(<RemediationList providerId={PROVIDER} />);

    const items = await screen.findAllByRole("listitem");
    const first = items[0];
    expect(
      within(first).getByText("Close open security group rules"),
    ).toBeVisible();
    expect(within(first).getByText(/opens a sensitive port/)).toBeVisible();
    expect(within(first).getByText("ec2_sg_ssh_open")).toBeVisible();
    expect(within(first).getByText("ec2_sg_rdp_open")).toBeVisible();
    expect(within(first).getByText(/Adds the same rule back/)).toBeVisible();
  });

  it("says whether each fix can be undone", async () => {
    render(<RemediationList providerId={PROVIDER} />);

    expect(await screen.findByText("Can be undone")).toBeVisible();
    expect(screen.getByText("Cannot be undone")).toBeVisible();
  });

  it("says whether each fix is inside the enforced frameworks, with the active checks", async () => {
    render(<RemediationList providerId={PROVIDER} />);

    expect(
      await screen.findByText(
        "In the enforced frameworks (1 of 2 checks active)",
      ),
    ).toBeVisible();
    expect(
      screen.getByText("Outside the enforced frameworks: never applied"),
    ).toBeVisible();
  });

  it("keeps the exact IAM actions collapsed until asked", async () => {
    const user = userEvent.setup();
    render(<RemediationList providerId={PROVIDER} />);

    expect(
      screen.queryByText("ec2:RevokeSecurityGroupIngress"),
    ).not.toBeInTheDocument();
    await user.click(
      await screen.findByRole("button", {
        name: /Exact AWS permissions \(2\)/,
      }),
    );

    expect(screen.getByText("ec2:RevokeSecurityGroupIngress")).toBeVisible();
    expect(screen.getByText("ec2:DescribeSecurityGroups")).toBeVisible();
  });

  it("asks without a provider and shows no scope when there is no account", async () => {
    render(<RemediationList />);

    await screen.findByText("Close open security group rules");
    expect(getRemediations).toHaveBeenCalledWith(undefined);
    expect(screen.queryByText(/enforced frameworks/)).not.toBeInTheDocument();
    expect(screen.getAllByText("Can be undone").length).toBeGreaterThan(0);
  });

  it("explains a 403 and still states the limits", async () => {
    getRemediations.mockResolvedValue({ ok: false, status: 403, error: "no" });
    render(<RemediationList providerId={PROVIDER} />);

    expect(
      await screen.findByText("You do not have access to this"),
    ).toBeVisible();
    expect(
      screen.getByText(/Nothing outside this list is ever fixed automatically/),
    ).toBeVisible();
  });

  it("explains a 503 as a notice, and an empty answer as empty", async () => {
    getRemediations.mockResolvedValue({ ok: false, status: 503, error: "x" });
    const { unmount } = render(<RemediationList providerId={PROVIDER} />);
    expect(
      await screen.findByText("Real-time data store not configured"),
    ).toBeVisible();
    unmount();

    getRemediations.mockResolvedValue({ ok: true, data: [] });
    render(<RemediationList providerId={PROVIDER} />);
    expect(await screen.findByText("No fixes are available yet")).toBeVisible();
  });
});
