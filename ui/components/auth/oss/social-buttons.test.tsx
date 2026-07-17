import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SocialButtons } from "./social-buttons";

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
