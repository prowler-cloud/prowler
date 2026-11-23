import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { buildCurrentLighthouseContext } from "@/hooks/use-lighthouse-context";
import {
  PROVIDER_FUNNEL_EVENT,
  type ProviderFunnelDetail,
} from "@/lib/provider-funnel/provider-funnel-events";
import { useLighthouseContextStore } from "@/store/lighthouse-context/store";
import { useLighthouseLlmStore } from "@/store/lighthouse-llm/store";
import { useProviderWizardStore } from "@/store/provider-wizard/store";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { LighthouseConnectHelp } from "./lighthouse-connect-help";

const { getConfigurationsMock, requestPanelSkillLaunchMock } = vi.hoisted(
  () => ({
    getConfigurationsMock: vi.fn(),
    requestPanelSkillLaunchMock: vi.fn(),
  }),
);

vi.mock("@/lib/shared/env", () => ({ isCloud: () => true }));
// jsdom has no matchMedia: emulate the viewport where the panel pushes.
vi.mock("@/hooks/use-media-query", () => ({ useMediaQuery: () => true }));
vi.mock("@/app/(prowler)/lighthouse/_actions", () => ({
  getLighthouseV2Configurations: getConfigurationsMock,
}));
vi.mock("@/app/(prowler)/lighthouse/_lib/panel-chat-store", () => ({
  requestPanelSkillLaunch: requestPanelSkillLaunchMock,
}));

const AWS_DOCS = "https://goto.prowler.com/provider-aws";

function renderHelp(
  providerType: string | null = "aws",
  connectionMethod: string | null = "role",
) {
  return render(
    <LighthouseConnectHelp
      docsLink={AWS_DOCS}
      docsDestination="AWS"
      providerType={providerType}
      mode="add"
      stepName="connect"
      stepLabel="Connect Provider"
      connectionMethod={connectionMethod}
      isOrganizationsFlow={false}
    />,
  );
}

// The context a follow-up typed in the panel carries on /providers.
function panelContextOnProviders() {
  return buildCurrentLighthouseContext(
    "/providers",
    new URLSearchParams(),
    Object.values(useLighthouseContextStore.getState().contributions),
  ).context;
}

// Collects the funnel signals dispatched until stop() is called.
function recordFunnelEvents() {
  const events: ProviderFunnelDetail[] = [];
  const record = (event: Event) =>
    events.push((event as CustomEvent<ProviderFunnelDetail>).detail);
  window.addEventListener(PROVIDER_FUNNEL_EVENT, record);
  return {
    stop: () => {
      window.removeEventListener(PROVIDER_FUNNEL_EVENT, record);
      return events;
    },
  };
}

function connectedConfiguration(connected: boolean) {
  return { data: [{ id: "config-1", connected }] };
}

// An LLM check the test settles by hand.
function pendingCheck() {
  let settle: (
    result: ReturnType<typeof connectedConfiguration>,
  ) => void = () => {};
  const promise = new Promise((resolve) => {
    settle = resolve;
  });
  return { promise, settle };
}

describe("LighthouseConnectHelp", () => {
  beforeEach(() => {
    getConfigurationsMock.mockResolvedValue(connectedConfiguration(true));
    useSidePanelStore.setState({
      isOpen: false,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
    });
    useProviderWizardStore.getState().reset();
    useLighthouseContextStore.setState({ contributions: {} });
    useLighthouseLlmStore.setState({ hasConnectedLlm: null, latestCheck: 0 });
  });

  it("invites the user to ask Lighthouse AI about the provider they picked", async () => {
    // When
    renderHelp("aws");

    // Then
    expect(
      await screen.findByRole("button", { name: "Ask Lighthouse AI" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Need a hand connecting AWS?")).toBeVisible();
    expect(screen.getByRole("link", { name: "AWS docs" })).toHaveAttribute(
      "href",
      AWS_DOCS,
    );
  });

  it("holds the callout's place while it checks for a connected LLM", async () => {
    // Given
    let settleCheck: (
      result: ReturnType<typeof connectedConfiguration>,
    ) => void = () => {};
    getConfigurationsMock.mockReturnValue(
      new Promise((resolve) => {
        settleCheck = resolve;
      }),
    );
    const funnelEvents = recordFunnelEvents();

    // When
    renderHelp("aws");

    // Then: a placeholder, never the docs line the callout would replace
    expect(
      screen.getByRole("status", { name: "Loading Lighthouse AI help" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("link", { name: /AWS documentation/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Ask Lighthouse AI" }),
    ).not.toBeInTheDocument();

    // When
    await act(async () => settleCheck(connectedConfiguration(true)));

    // Then
    expect(
      screen.getByRole("button", { name: "Ask Lighthouse AI" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("status", { name: "Loading Lighthouse AI help" }),
    ).not.toBeInTheDocument();
    expect(funnelEvents.stop()).toHaveLength(1);
  });

  it("shows the last answer at once when the wizard opens again, then refreshes it", async () => {
    // Given: an earlier opening found a connected LLM
    const firstOpening = renderHelp("aws");
    await screen.findByRole("button", { name: "Ask Lighthouse AI" });
    firstOpening.unmount();
    let settleCheck: (
      result: ReturnType<typeof connectedConfiguration>,
    ) => void = () => {};
    getConfigurationsMock.mockReturnValue(
      new Promise((resolve) => {
        settleCheck = resolve;
      }),
    );

    // When
    renderHelp("aws");

    // Then: no placeholder while the fresh check runs
    expect(
      screen.getByRole("button", { name: "Ask Lighthouse AI" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("status", { name: "Loading Lighthouse AI help" }),
    ).not.toBeInTheDocument();

    // When: the LLM was disconnected meanwhile
    await act(async () => settleCheck(connectedConfiguration(false)));

    // Then
    expect(
      screen.queryByRole("button", { name: "Ask Lighthouse AI" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /AWS documentation/i }),
    ).toBeVisible();
  });

  it("ignores an older check that answers after a newer opening", async () => {
    // Given: the wizard closes while its check runs, then opens again
    const olderCheck = pendingCheck();
    const newerCheck = pendingCheck();
    getConfigurationsMock
      .mockReturnValueOnce(olderCheck.promise)
      .mockReturnValueOnce(newerCheck.promise);
    const firstOpening = renderHelp("aws");
    await waitFor(() => expect(getConfigurationsMock).toHaveBeenCalledOnce());
    firstOpening.unmount();
    renderHelp("aws");
    await waitFor(() => expect(getConfigurationsMock).toHaveBeenCalledTimes(2));

    // When: the newer check answers first, then the older one
    await act(async () => newerCheck.settle(connectedConfiguration(false)));
    await act(async () => olderCheck.settle(connectedConfiguration(true)));

    // Then
    expect(
      screen.queryByRole("button", { name: "Ask Lighthouse AI" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /AWS documentation/i }),
    ).toBeVisible();
  });

  it("keeps the remembered answer when a later check fails", async () => {
    // Given: an earlier opening found a connected LLM
    const firstOpening = renderHelp("aws");
    await screen.findByRole("button", { name: "Ask Lighthouse AI" });
    firstOpening.unmount();
    getConfigurationsMock.mockRejectedValueOnce(new Error("network"));

    // When
    renderHelp("aws");
    await waitFor(() => expect(getConfigurationsMock).toHaveBeenCalledTimes(2));
    await act(() => Promise.resolve());

    // Then: a failed refresh does not swap the callout for the docs line
    expect(
      screen.getByRole("button", { name: "Ask Lighthouse AI" }),
    ).toBeVisible();
  });

  it("falls back to the documentation link when the check fails", async () => {
    // Given
    getConfigurationsMock.mockRejectedValue(new Error("network"));

    // When
    renderHelp("aws");

    // Then
    expect(
      await screen.findByRole("link", { name: /AWS documentation/i }),
    ).toBeVisible();
    expect(
      screen.queryByRole("status", { name: "Loading Lighthouse AI help" }),
    ).not.toBeInTheDocument();
  });

  it("keeps only the documentation link while Lighthouse AI is not set up", async () => {
    // Given
    getConfigurationsMock.mockResolvedValue(connectedConfiguration(false));
    const funnelEvents = recordFunnelEvents();

    // When
    renderHelp("aws");
    await waitFor(() => expect(getConfigurationsMock).toHaveBeenCalled());
    await act(() => Promise.resolve());

    // Then: nothing was offered, so nothing counts as shown
    expect(
      screen.queryByRole("button", { name: "Ask Lighthouse AI" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /AWS documentation/i }),
    ).toHaveAttribute("href", AWS_DOCS);
    expect(funnelEvents.stop()).toEqual([]);
  });

  it("reports the offer once, with the step where it first appeared", async () => {
    // Given
    const funnelEvents = recordFunnelEvents();
    const { rerender } = renderHelp("aws");
    await screen.findByRole("button", { name: "Ask Lighthouse AI" });

    // When: the user moves on to the next step with the callout still there
    rerender(
      <LighthouseConnectHelp
        docsLink={AWS_DOCS}
        docsDestination="AWS"
        providerType="aws"
        mode="add"
        stepName="launch"
        stepLabel="Launch Scan"
        connectionMethod="credentials"
        isOrganizationsFlow={false}
      />,
    );

    // Then
    expect(funnelEvents.stop()).toEqual([
      {
        step: "lighthouse_help_shown",
        providerType: "aws",
        wizardStep: "connect",
      },
    ]);
  });

  it("asks for a connection guide about the current step without sharing typed credentials", async () => {
    // Given: the user switched AWS to access keys and typed a secret
    const user = userEvent.setup();
    useProviderWizardStore.getState().setConnectDraft("aws", {
      method: "credentials",
      values: { credentials: { aws_secret_access_key: "super-secret-value" } },
    });
    renderHelp("aws", "credentials");
    const askButton = await screen.findByRole("button", {
      name: "Ask Lighthouse AI",
    });
    const funnelEvents = recordFunnelEvents();

    // When
    await user.click(askButton);

    // Then: the AI tab opens and runs the guide with the wizard state
    expect(useSidePanelStore.getState()).toMatchObject({
      isOpen: true,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
    });
    await waitFor(() => expect(requestPanelSkillLaunchMock).toHaveBeenCalled());
    const [skill, context] = requestPanelSkillLaunchMock.mock.calls[0];
    expect(skill.id).toBe("provider-connection-guide");
    expect(context.items[0]).toMatchObject({
      kind: "provider",
      providerType: "aws",
      wizardStep: "connect",
      connectionMethod: "credentials",
      docsUrl: AWS_DOCS,
    });
    expect(JSON.stringify(context)).not.toContain("super-secret-value");
    expect(funnelEvents.stop()).toEqual([
      {
        step: "lighthouse_help_opened",
        providerType: "aws",
        wizardStep: "connect",
      },
    ]);
  });

  it("offers help with the current step while Lighthouse AI is already guiding", async () => {
    // Given
    useSidePanelStore.setState({
      isOpen: true,
      selectedTab: SIDE_PANEL_TAB.AI_CHAT,
    });

    // When
    renderHelp("aws");

    // Then
    expect(
      await screen.findByRole("button", { name: "Ask about this step" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Lighthouse AI is guiding you")).toBeVisible();
  });

  it("keeps follow-ups in the panel aware of the step and method the user is on", async () => {
    // Given: the guide was opened on the connect step
    const { rerender, unmount } = renderHelp("aws");
    await screen.findByRole("button", { name: "Ask Lighthouse AI" });

    // When: the user switches to access keys and moves on to the next step
    act(() =>
      useProviderWizardStore.getState().setConnectDraft("aws", {
        method: "credentials",
        values: {
          credentials: { aws_secret_access_key: "super-secret-value" },
        },
      }),
    );
    rerender(
      <LighthouseConnectHelp
        docsLink={AWS_DOCS}
        docsDestination="AWS"
        providerType="aws"
        mode="add"
        stepName="launch"
        stepLabel="Launch Scan"
        connectionMethod="credentials"
        isOrganizationsFlow={false}
      />,
    );

    // Then: a follow-up carries the current wizard state, never the secret
    const followUpContext = panelContextOnProviders();
    expect(followUpContext?.items).toContainEqual(
      expect.objectContaining({
        kind: "provider",
        providerType: "aws",
        wizardStep: "launch",
        connectionMethod: "credentials",
      }),
    );
    expect(JSON.stringify(followUpContext)).not.toContain("super-secret-value");

    // When: the wizard closes
    unmount();

    // Then
    expect(
      panelContextOnProviders()?.items.some((item) => item.kind === "provider"),
    ).toBe(false);
  });

  it("leaves a provider account from an earlier wizard out of organization setup", async () => {
    // Given: sessionStorage still holds the account of an earlier provider wizard
    const user = userEvent.setup();
    useProviderWizardStore.getState().setProvider({
      id: "provider-1",
      type: "aws",
      uid: "111122223333",
      alias: null,
    });
    render(
      <LighthouseConnectHelp
        docsLink={AWS_DOCS}
        docsDestination="AWS"
        providerType="aws"
        mode="add"
        stepName="setup"
        stepLabel="Organization Setup"
        connectionMethod="organizations"
        isOrganizationsFlow
      />,
    );

    // When
    await user.click(
      await screen.findByRole("button", { name: "Ask Lighthouse AI" }),
    );

    // Then: neither the guide nor follow-ups mention that account
    await waitFor(() => expect(requestPanelSkillLaunchMock).toHaveBeenCalled());
    const [, launchContext] = requestPanelSkillLaunchMock.mock.calls[0];
    expect(JSON.stringify(launchContext)).not.toContain("111122223333");
    expect(JSON.stringify(panelContextOnProviders())).not.toContain(
      "111122223333",
    );
    expect(launchContext.items[0]).toMatchObject({
      connectionMethod: "organizations",
    });
  });
});
