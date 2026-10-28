import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SocialButtons } from "./social-buttons";

describe("SocialButtons", () => {
  it("renders icon-only provider links that keep their accessible names", () => {
    render(
      <SocialButtons
        googleAuthUrl="https://accounts.google.com/auth"
        githubAuthUrl="https://github.com/login/oauth"
        microsoftAuthUrl="https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
        isGoogleOAuthEnabled
        isGithubOAuthEnabled
        isMicrosoftOAuthEnabled
      />,
    );

    const google = screen.getByRole("link", { name: "Continue with Google" });
    const github = screen.getByRole("link", { name: "Continue with Github" });
    const microsoft = screen.getByRole("link", {
      name: "Continue with Microsoft",
    });

    expect(google.textContent).toBe("");
    expect(github.textContent).toBe("");
    expect(microsoft.textContent).toBe("");
  });

  it("renders bundled provider logos without fetching icon data", () => {
    render(
      <SocialButtons
        googleAuthUrl="https://accounts.google.com/auth"
        githubAuthUrl="https://github.com/login/oauth"
        microsoftAuthUrl="https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
        isGoogleOAuthEnabled
        isGithubOAuthEnabled
        isMicrosoftOAuthEnabled
      />,
    );

    const google = screen.getByRole("link", { name: "Continue with Google" });
    const github = screen.getByRole("link", { name: "Continue with Github" });
    const microsoft = screen.getByRole("link", {
      name: "Continue with Microsoft",
    });

    expect(google.querySelector("svg path")).toBeInTheDocument();
    expect(github.querySelector("svg path")).toBeInTheDocument();
    expect(microsoft.querySelector("svg path")).toBeInTheDocument();
  });

  it("keeps accessible names on disabled providers", () => {
    render(<SocialButtons />);

    expect(
      screen.getByRole("button", { name: "Continue with Google" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Continue with Github" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Continue with Microsoft" }),
    ).toBeDisabled();
  });
});
