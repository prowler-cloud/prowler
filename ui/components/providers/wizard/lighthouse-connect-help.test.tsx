import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { buildCurrentLighthouseContext } from "@/hooks/use-lighthouse-context";
import {
  PROVIDER_FUNNEL_EVENT,
  type ProviderFunnelDetail,
} from "@/lib/provider-funnel/provider-funnel-events";
import { useLighthouseContextStore } from "@/store/lighthouse-context/store";
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

function renderHelp(providerType: string | null = "aws") {
  return render(
    <LighthouseConnectHelp
      docsLink={AWS_DOCS}
      docsDestination="AWS"
      providerType={providerType}
      mode="add"
      stepName="connect"
      stepLabel="Link a Provider"
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

function connectedConfiguration(connected: boolean) {
  return { data: [{ id: "config-1", connected }] };
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

  it("keeps only the documentation link while Lighthouse AI is not set up", async () => {
    // Given
    getConfigurationsMock.mockResolvedValue(connectedConfiguration(false));

    // When
    renderHelp("aws");
    await waitFor(() => expect(getConfigurationsMock).toHaveBeenCalled());
    await act(() => Promise.resolve());

    // Then
    expect(
      screen.queryByRole("button", { name: "Ask Lighthouse AI" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /AWS documentation/i }),
    ).toHaveAttribute("href", AWS_DOCS);
  });

  it("asks for a connection guide about the current step without sharing typed credentials", async () => {
    // Given: the user switched AWS to access keys and typed a secret
    const user = userEvent.setup();
    useProviderWizardStore.getState().setAwsConnectDraft({
      method: "credentials",
      keysValues: { awsSecretAccessKey: "super-secret-value" },
    });
    const funnelEvents: ProviderFunnelDetail[] = [];
    const recordFunnelEvent = (event: Event) =>
      funnelEvents.push((event as CustomEvent<ProviderFunnelDetail>).detail);
    window.addEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelEvent);
    renderHelp("aws");

    // When
    await user.click(
      await screen.findByRole("button", { name: "Ask Lighthouse AI" }),
    );

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
    expect(funnelEvents).toEqual([
      {
        step: "lighthouse_help_opened",
        providerType: "aws",
        wizardStep: "connect",
      },
    ]);
    window.removeEventListener(PROVIDER_FUNNEL_EVENT, recordFunnelEvent);
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
      useProviderWizardStore.getState().setAwsConnectDraft({
        method: "credentials",
        keysValues: { awsSecretAccessKey: "super-secret-value" },
      }),
    );
    rerender(
      <LighthouseConnectHelp
        docsLink={AWS_DOCS}
        docsDestination="AWS"
        providerType="aws"
        mode="add"
        stepName="test"
        stepLabel="Test Connection"
        isOrganizationsFlow={false}
      />,
    );

    // Then: a follow-up carries the current wizard state, never the secret
    const followUpContext = panelContextOnProviders();
    expect(followUpContext?.items).toContainEqual(
      expect.objectContaining({
        kind: "provider",
        providerType: "aws",
        wizardStep: "test",
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
