import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/actions/realtime", () => ({}));
vi.mock("@/components/shadcn/toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

import type {
  RealtimeAction,
  RealtimeEvent,
  RealtimeRankedFinding,
  RealtimeSimulationPayload,
} from "@/types/realtime";

import { ActionsTable } from "./actions-list";
import { actorLabel, EventsTable } from "./events-table";
import { RankedFindingsTable } from "./findings-tab";
import { SimulationCard } from "./simulation-card";

const action = (overrides: Partial<RealtimeAction>): RealtimeAction => ({
  id: "a1",
  provider_id: "p",
  detection_id: null,
  kind: "self_fix",
  status: "fixed_verified",
  check_id: "s3_bucket_level_public_access_block",
  resource_uid: "bucket-1",
  region: "eu-west-1",
  severity: "high",
  summary: "Enabled public access block",
  pr_url: "",
  branch: "",
  revertible: false,
  inserted_at: "2026-10-23T10:00:00Z",
  ...overrides,
});

describe("ActionsTable", () => {
  it("shows Revert only for revertible actions and confirms through the callback", async () => {
    const user = userEvent.setup();
    const onRevert = vi.fn();
    const revertible = action({ id: "a1", revertible: true });
    render(
      <ActionsTable
        actions={[revertible, action({ id: "a2", resource_uid: "bucket-2" })]}
        canManage
        onRevert={onRevert}
      />,
    );

    const buttons = screen.getAllByRole("button", { name: "Revert" });
    expect(buttons).toHaveLength(1);
    await user.click(buttons[0]);
    expect(onRevert).toHaveBeenCalledWith(revertible);
  });

  it("disables Revert without the permission", () => {
    render(
      <ActionsTable
        actions={[action({ revertible: true })]}
        canManage={false}
        onRevert={vi.fn()}
      />,
    );

    expect(screen.getByRole("button", { name: "Revert" })).toBeDisabled();
  });

  it("links only safe pull request URLs", () => {
    render(
      <ActionsTable
        actions={[
          action({
            id: "a1",
            status: "pr_opened",
            pr_url: "https://github.com/a/b/pull/1",
          }),
          action({ id: "a2", pr_url: "javascript:alert(1)" }),
        ]}
        canManage
        onRevert={vi.fn()}
      />,
    );

    const links = screen.getAllByRole("link", { name: "View pull request" });
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("marks Lighthouse AI code fixes and rejected proposals", () => {
    render(
      <ActionsTable
        actions={[
          action({
            id: "l1",
            kind: "code",
            status: "pr_opened",
            summary: "Lighthouse AI fix for s3_bucket_versioning",
          }),
          action({
            id: "l2",
            kind: "proposal",
            status: "pr_blocked",
            summary: "Lighthouse AI proposal rejected by the security gate",
          }),
          action({ id: "l3", summary: "Enabled public access block" }),
        ]}
        canManage
        onRevert={vi.fn()}
      />,
    );

    expect(screen.getAllByText("Lighthouse AI")).toHaveLength(2);
  });

  it("renders the empty state", () => {
    render(<ActionsTable actions={[]} canManage onRevert={vi.fn()} />);

    expect(
      screen.getByText("Prowler Realtime has not acted yet"),
    ).toBeVisible();
  });
});

const event = (overrides: Partial<RealtimeEvent>): RealtimeEvent => ({
  id: "e1",
  event_time: "2026-10-23T10:00:00Z",
  region: "eu-west-1",
  event_source: "ec2.amazonaws.com",
  event_name: "AuthorizeSecurityGroupIngress",
  user_type: "IAMUser",
  user_arn: "arn:aws:iam::123456789012:user/ana",
  source_ip: "203.0.113.9",
  error_code: "",
  read_only: false,
  provider_id: "p",
  detection_status: null,
  rule_id: null,
  ...overrides,
});

describe("EventsTable", () => {
  it("shows the detection badge, region, actor and IP", () => {
    render(
      <EventsTable
        events={[
          event({ detection_status: "violation", rule_id: "sg_open" }),
          event({ id: "e2", event_name: "DescribeInstances", read_only: true }),
        ]}
        writesOnly={false}
      />,
    );

    const rows = screen.getAllByRole("row");
    expect(within(rows[1]).getByText("Violation")).toBeVisible();
    expect(within(rows[1]).getByText("sg_open")).toBeVisible();
    expect(within(rows[1]).getByText("user/ana")).toBeVisible();
    expect(within(rows[1]).getByText("203.0.113.9")).toBeVisible();
    expect(within(rows[2]).getByText("None")).toBeVisible();
  });

  it("derives the actor from the ARN or the user type", () => {
    expect(actorLabel(event({}))).toBe("user/ana");
    expect(actorLabel(event({ user_arn: "", user_type: "AWSService" }))).toBe(
      "AWSService",
    );
  });

  it("explains an empty stream", () => {
    render(<EventsTable events={[]} writesOnly />);

    expect(screen.getByText("No events in the last 24 hours")).toBeVisible();
  });
});

describe("RankedFindingsTable", () => {
  const finding = (overrides: Partial<RealtimeRankedFinding>) =>
    ({
      finding_id: "f1",
      check_id: "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
      severity: "high",
      title: "SSH open to the internet",
      service: "ec2",
      resource_uid: "sg-1",
      region: "eu-west-1",
      status_extended: "",
      score: 110,
      reasons: ["cost spike in ec2"],
      route: "auto",
      ...overrides,
    }) as RealtimeRankedFinding;

  it("shows score, reasons and the route badge", () => {
    render(
      <RankedFindingsTable
        findings={[
          finding({}),
          finding({
            finding_id: "f2",
            route: "manual",
            reasons: [],
            score: 70,
          }),
          finding({ finding_id: "f3", route: "pr" }),
        ]}
      />,
    );

    expect(screen.getAllByText("110").length).toBeGreaterThan(0);
    expect(screen.getAllByText("cost spike in ec2")).toHaveLength(2);
    const table = within(screen.getByRole("table"));
    expect(table.getByText("Auto-fix")).toBeVisible();
    expect(table.getByText("Needs a person")).toBeVisible();
    expect(table.getByText("Pull request")).toBeVisible();
    expect(screen.getByText("Severity only")).toBeVisible();
  });

  it("labels findings outside the enforced frameworks and explains every route", () => {
    render(
      <RankedFindingsTable
        findings={[finding({ finding_id: "f9", route: "not_enforced" })]}
      />,
    );

    const legend = screen.getByLabelText("Handled by legend");
    expect(within(legend).getAllByText("Not enforced")).toHaveLength(1);
    expect(
      within(legend).getByText(/Outside the enforced compliance frameworks/),
    ).toBeVisible();
    expect(within(legend).getByText("Auto-fix")).toBeVisible();
    expect(
      within(screen.getByRole("table")).getByText("Not enforced"),
    ).toBeVisible();
  });
});

describe("SimulationCard", () => {
  const simulation = (
    overrides: Partial<RealtimeSimulationPayload>,
  ): RealtimeSimulationPayload => ({
    open: 10,
    would_fix_in_account: 4,
    would_propose_in_code: 3,
    needs_a_person: 3,
    outside_frameworks: 0,
    frameworks: [],
    dry_run: true,
    mode: "auto",
    effects: [
      {
        check_id: "rds_instance_no_public_access",
        effect: "Set PubliclyAccessible to false (undo recorded)",
        resources: 2,
      },
    ],
    projected_open_after_auto: 6,
    automation_share: 40,
    ...overrides,
  });

  it("states the three outcomes, the effects and the dry-run caveat", () => {
    render(<SimulationCard simulation={simulation({})} />);

    expect(screen.getByText("fixed in the account")).toBeVisible();
    expect(screen.getByText("pull requests")).toBeVisible();
    expect(screen.getByText("need a person")).toBeVisible();
    expect(screen.getByText(/Set PubliclyAccessible/)).toBeVisible();
    expect(screen.getByText("Dry run is on")).toBeVisible();
  });

  it("states how many findings are outside the enforced frameworks", () => {
    render(
      <SimulationCard
        simulation={simulation({
          outside_frameworks: 7,
          frameworks: ["soc2_aws"],
        })}
      />,
    );

    expect(screen.getByText(/outside the enforced frameworks/)).toBeVisible();
    expect(screen.getByText("7")).toBeVisible();
  });

  it("says nothing about frameworks when none are outside", () => {
    render(<SimulationCard simulation={simulation({})} />);

    expect(
      screen.queryByText(/outside the enforced frameworks/),
    ).not.toBeInTheDocument();
  });

  it("warns that fixes will be applied when dry run is off", () => {
    render(<SimulationCard simulation={simulation({ dry_run: false })} />);

    expect(screen.getByText("Dry run is off")).toBeVisible();
  });

  it("says automatic fixes are not counted outside auto mode", () => {
    render(
      <SimulationCard
        simulation={simulation({ mode: "pr", would_fix_in_account: 0 })}
      />,
    );

    expect(
      screen.getByText(/Automatic fixes in the account are off/),
    ).toBeVisible();
    expect(screen.queryByText("Dry run is on")).not.toBeInTheDocument();
  });
});
