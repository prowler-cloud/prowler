import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SocialButtons } from "./social-buttons";

// Stub Iconify: the real <Icon> fetches icon data over the network and its
// retry timers can fire after the jsdom environment is torn down, crashing the
// worker with "window is not defined".
vi.mock("@iconify/react", () => ({
  Icon: ({ icon }: { icon: string }) => <span aria-label={icon} />,
}));

describe("SocialButtons", () => {
  it("renders icon-only provider links that keep their accessible names", () => {
    render(
      <SocialButtons
        googleAuthUrl="https://accounts.google.com/auth"
        githubAuthUrl="https://github.com/login/oauth"
        isGoogleOAuthEnabled
        isGithubOAuthEnabled
      />,
    );

    const google = screen.getByRole("link", { name: "Continue with Google" });
    const github = screen.getByRole("link", { name: "Continue with Github" });

    expect(google.textContent).toBe("");
    expect(github.textContent).toBe("");
  });

  it("keeps accessible names on disabled providers", () => {
    render(<SocialButtons />);

    expect(
      screen.getByRole("button", { name: "Continue with Google" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Continue with Github" }),
    ).toBeDisabled();
  });
});
