import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { SIDEBAR_NAVIGATION_MODE } from "@/hooks/use-sidebar";

const {
  openLaunchScanModalMock,
  pathnameValue,
  pushMock,
  navigationModeValue,
  setNavigationModeMock,
} = vi.hoisted(() => ({
  openLaunchScanModalMock: vi.fn(),
  pathnameValue: { current: "/findings" },
  pushMock: vi.fn(),
  navigationModeValue: { current: "browse" },
  setNavigationModeMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => pathnameValue.current,
  useRouter: () => ({
    push: pushMock,
  }),
}));

vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: { user: { permissions: {} } },
    status: "authenticated",
  }),
}));

vi.mock("@/hooks", () => ({
  useAuth: () => ({
    permissions: {},
  }),
}));

vi.mock("@/lib/menu-list", () => ({
  getMenuList: () => [],
}));

vi.mock("@/app/(prowler)/lighthouse/_components/navigation", () => ({
  LighthouseV2SidebarChat: () => <div data-testid="lighthouse-chat-sidebar" />,
}));

vi.mock("@/store", () => ({
  useScansStore: (
    selector: (state: { openLaunchScanModal: () => void }) => unknown,
  ) => selector({ openLaunchScanModal: openLaunchScanModalMock }),
}));

vi.mock("@/hooks/use-sidebar", async (importActual) => {
  const actual = await importActual<typeof import("@/hooks/use-sidebar")>();
  return {
    ...actual,
    useSidebar: (
      selector: (state: {
        navigationMode: string;
        setNavigationMode: (mode: string) => void;
      }) => unknown,
    ) =>
      selector({
        navigationMode: navigationModeValue.current,
        setNavigationMode: setNavigationModeMock,
      }),
  };
});

let MenuComponent: typeof import("./menu").Menu;
let SidebarNavigationModeToggleComponent: typeof import("@/components/sidebar/navigation-mode-toggle").SidebarNavigationModeToggle;

beforeAll(async () => {
  MenuComponent = (await import("./menu")).Menu;
  SidebarNavigationModeToggleComponent = (
    await import("@/components/sidebar/navigation-mode-toggle")
  ).SidebarNavigationModeToggle;
});

afterEach(() => {
  vi.unstubAllEnvs();
  navigationModeValue.current = "browse";
});

describe("Menu", () => {
  it("links scan to the scans page with the modal open", () => {
    pathnameValue.current = "/findings";

    render(<MenuComponent isOpen />);

    const launchScanLink = screen.getByRole("link", { name: /launch scan/i });
    const launchScanWrapper = launchScanLink.closest("div.flex.shrink-0");

    expect(launchScanLink).toHaveAttribute("href", "/scans?launchScan=true");
    expect(launchScanWrapper).toHaveClass("flex", "justify-center");
    expect(launchScanLink).toHaveClass("h-14", "w-full", "p-1");
    expect(launchScanLink).not.toHaveClass("h-8", "h-9", "h-10");
    expect(screen.getByText("Scan")).toHaveClass("text-xl", "leading-8");
    expect(screen.getByText("Scan")).not.toHaveClass("text-2xl", "font-bold");
    expect(
      launchScanLink.querySelector('svg[viewBox="0 0 432.08 396.77"]'),
    ).toBeInTheDocument();
  });

  it("opens the launch scan modal without navigation when already on scans", async () => {
    pathnameValue.current = "/scans";

    render(<MenuComponent isOpen />);

    await screen.getByRole("button", { name: /launch scan/i }).click();

    expect(openLaunchScanModalMock).toHaveBeenCalledTimes(1);
    expect(
      screen.queryByRole("link", { name: /launch scan/i }),
    ).not.toBeInTheDocument();
  });

  it("shows the Prowler icon when the menu is collapsed", () => {
    pathnameValue.current = "/findings";

    render(<MenuComponent isOpen={false} />);

    const launchScanLink = screen.getByRole("link", { name: /launch scan/i });

    expect(launchScanLink).toHaveClass("h-9", "w-14");
    expect(launchScanLink).not.toHaveClass("h-14");
    expect(
      launchScanLink.querySelector('svg[viewBox="0 0 432.08 396.77"]'),
    ).toBeInTheDocument();
  });

  it("swaps to the Lighthouse chat sidebar in cloud CHAT mode", () => {
    pathnameValue.current = "/lighthouse";
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    navigationModeValue.current = SIDEBAR_NAVIGATION_MODE.CHAT;

    render(<MenuComponent isOpen />);

    expect(screen.getByTestId("lighthouse-chat-sidebar")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Chat" })).toBeInTheDocument();
  });

  it("keeps the navigation menu in cloud BROWSE mode", () => {
    pathnameValue.current = "/findings";
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    navigationModeValue.current = SIDEBAR_NAVIGATION_MODE.BROWSE;

    render(<MenuComponent isOpen />);

    expect(
      screen.queryByTestId("lighthouse-chat-sidebar"),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Home" })).toBeInTheDocument();
  });

  it("shows the mode toggle with Chat disabled outside cloud", () => {
    pathnameValue.current = "/findings";
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");

    render(<MenuComponent isOpen />);

    expect(screen.getByRole("button", { name: "Home" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Chat" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  });
});

describe("SidebarNavigationModeToggle", () => {
  beforeEach(() => {
    pushMock.mockClear();
  });

  it("navigates to Lighthouse when Chat mode is selected", async () => {
    // Given
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <SidebarNavigationModeToggleComponent
        isOpen
        value={SIDEBAR_NAVIGATION_MODE.BROWSE}
        onChange={onChange}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Chat" }));

    // Then
    expect(onChange).toHaveBeenCalledWith(SIDEBAR_NAVIGATION_MODE.CHAT);
    expect(pushMock).toHaveBeenCalledWith("/lighthouse");
  });

  it("does not navigate when Home mode is selected", async () => {
    // Given
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <SidebarNavigationModeToggleComponent
        isOpen
        value={SIDEBAR_NAVIGATION_MODE.CHAT}
        onChange={onChange}
      />,
    );

    // When
    await user.click(screen.getByRole("button", { name: "Home" }));

    // Then
    expect(onChange).toHaveBeenCalledWith(SIDEBAR_NAVIGATION_MODE.BROWSE);
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("blocks Chat and shows the cloud tooltip when chat is unavailable", async () => {
    // Given
    const user = userEvent.setup();
    const onChange = vi.fn();

    render(
      <SidebarNavigationModeToggleComponent
        isOpen
        value={SIDEBAR_NAVIGATION_MODE.BROWSE}
        onChange={onChange}
        chatEnabled={false}
      />,
    );

    // When
    const chatButton = screen.getByRole("button", { name: "Chat" });
    await user.hover(chatButton);

    // Then
    const tooltip = await screen.findByRole("tooltip");
    expect(tooltip).toHaveTextContent("Available in Prowler Cloud");

    // When
    await user.click(chatButton);

    // Then
    expect(onChange).not.toHaveBeenCalled();
    expect(pushMock).not.toHaveBeenCalled();
  });
});
