import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CliImportBanner } from "./cli-import-banner";

const STORAGE_KEY = "prowler:cli-import-banner-dismissed";

const localStorageMock = (() => {
  let store: Record<string, string> = {};

  return {
    getItem: vi.fn((key: string) => store[key] ?? null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value;
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    get length() {
      return Object.keys(store).length;
    },
    key: vi.fn((index: number) => Object.keys(store)[index] ?? null),
  };
})();

Object.defineProperty(window, "localStorage", {
  value: localStorageMock,
  writable: true,
});

describe("CliImportBanner", () => {
  beforeEach(() => {
    localStorageMock.clear();
    vi.clearAllMocks();
  });

  it("renders the banner when not dismissed", () => {
    render(<CliImportBanner />);

    expect(
      screen.getByText(/Import findings from Prowler CLI/),
    ).toBeInTheDocument();
  });

  it("links to the internal CLI Import guide", () => {
    render(<CliImportBanner />);

    const link = screen.getByRole("link", { name: "Learn more" });

    expect(link).toHaveAttribute("href", "/scans/import");
    expect(link).not.toHaveAttribute("target");
    expect(link).not.toHaveAttribute("rel");
  });

  it("does not render when previously dismissed", () => {
    localStorageMock.setItem(STORAGE_KEY, "true");

    const { container } = render(<CliImportBanner />);

    expect(container).toBeEmptyDOMElement();
  });

  it("dismisses the banner and persists to localStorage on close", async () => {
    const user = userEvent.setup();

    render(<CliImportBanner />);

    const closeButton = screen.getByRole("button", { name: "Close" });

    await user.click(closeButton);

    expect(
      screen.queryByText(/Import findings from Prowler CLI/),
    ).not.toBeInTheDocument();
    expect(localStorageMock.setItem).toHaveBeenCalledWith(STORAGE_KEY, "true");
  });

  it("renders with role='alert'", () => {
    render(<CliImportBanner />);

    expect(screen.getByRole("alert")).toBeInTheDocument();
  });
});
