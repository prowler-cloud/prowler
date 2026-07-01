import { Tooltip } from "@heroui/tooltip";
import { Icon } from "@iconify/react";
import type { ReactNode } from "react";

import { Button } from "@/components/shadcn";
import { CustomLink } from "@/components/ui/custom/custom-link";
import { appendCallbackState } from "@/lib/auth-callback-url";

export const SocialButtons = ({
  googleAuthUrl,
  githubAuthUrl,
  callbackUrl = "/",
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
  isDisabled = false,
  disabledTooltipContent,
}: {
  googleAuthUrl?: string;
  githubAuthUrl?: string;
  callbackUrl?: string;
  isGoogleOAuthEnabled?: boolean;
  isGithubOAuthEnabled?: boolean;
  isDisabled?: boolean;
  disabledTooltipContent?: ReactNode;
}) => {
  const googleUrl = googleAuthUrl
    ? appendCallbackState(googleAuthUrl, callbackUrl)
    : undefined;
  const githubUrl = githubAuthUrl
    ? appendCallbackState(githubAuthUrl, callbackUrl)
    : undefined;
  const isGoogleDisabled = isDisabled || !isGoogleOAuthEnabled || !googleUrl;
  const isGithubDisabled = isDisabled || !isGithubOAuthEnabled || !githubUrl;
  const socialDisabledTooltip =
    disabledTooltipContent || "Social login is currently unavailable.";

  return (
    <>
      <Tooltip
        content={
          isGoogleOAuthEnabled ? (
            socialDisabledTooltip
          ) : (
            <div className="flex-inline text-small">
              Social Login with Google is not enabled.{" "}
              <CustomLink href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-social-login/#google-oauth-configuration">
                Read the docs
              </CustomLink>
            </div>
          )
        }
        placement="top"
        shadow="sm"
        isDisabled={!isGoogleDisabled}
        className="w-96"
      >
        <span>
          <Button
            variant="outline"
            className="w-full"
            asChild={!isGoogleDisabled}
            disabled={isGoogleDisabled}
          >
            {isGoogleDisabled ? (
              <span className="flex items-center gap-2">
                <Icon
                  icon={
                    isGoogleOAuthEnabled
                      ? "flat-color-icons:google"
                      : "simple-icons:google"
                  }
                  width={24}
                />
                Continue with Google
              </span>
            ) : (
              <a href={googleUrl} className="flex items-center gap-2">
                <Icon icon="flat-color-icons:google" width={24} />
                Continue with Google
              </a>
            )}
          </Button>
        </span>
      </Tooltip>
      <Tooltip
        content={
          isGithubOAuthEnabled ? (
            socialDisabledTooltip
          ) : (
            <div className="flex-inline text-small">
              Social Login with Github is not enabled.{" "}
              <CustomLink href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-social-login/#github-oauth-configuration">
                Read the docs
              </CustomLink>
            </div>
          )
        }
        placement="top"
        shadow="sm"
        isDisabled={!isGithubDisabled}
        className="w-96"
      >
        <span>
          <Button
            variant="outline"
            className="w-full"
            asChild={!isGithubDisabled}
            disabled={isGithubDisabled}
          >
            {isGithubDisabled ? (
              <span className="flex items-center gap-2">
                <Icon icon="simple-icons:github" width={24} />
                Continue with Github
              </span>
            ) : (
              <a href={githubUrl} className="flex items-center gap-2">
                <Icon icon="simple-icons:github" width={24} />
                Continue with Github
              </a>
            )}
          </Button>
        </span>
      </Tooltip>
    </>
  );
};
