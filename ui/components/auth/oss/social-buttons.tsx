import { Tooltip } from "@heroui/tooltip";
import { Icon } from "@iconify/react";

import { Button } from "@/components/shadcn";
import { CustomLink } from "@/components/ui/custom/custom-link";

export const SocialButtons = ({
  googleAuthUrl,
  githubAuthUrl,
  isGoogleOAuthEnabled,
  isGithubOAuthEnabled,
}: {
  googleAuthUrl?: string;
  githubAuthUrl?: string;
  isGoogleOAuthEnabled?: boolean;
  isGithubOAuthEnabled?: boolean;
}) => (
  <>
    <Tooltip
      content={
        <div className="flex-inline text-small">
          Social Login with Google is not enabled.{" "}
          <CustomLink href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-social-login/#google-oauth-configuration">
            Read the docs
          </CustomLink>
        </div>
      }
      placement="top"
      shadow="sm"
      isDisabled={isGoogleOAuthEnabled}
      className="w-96"
    >
      <span>
        <Button
          variant="outline"
          className="w-full"
          asChild={isGoogleOAuthEnabled}
          disabled={!isGoogleOAuthEnabled}
        >
          <a href={googleAuthUrl} className="flex items-center gap-2">
            <Icon
              icon={
                isGoogleOAuthEnabled
                  ? "flat-color-icons:google"
                  : "simple-icons:google"
              }
              width={24}
            />
            Continue with Google
          </a>
        </Button>
      </span>
    </Tooltip>
    <Tooltip
      content={
        <div className="flex-inline text-small">
          Social Login with Github is not enabled.{" "}
          <CustomLink href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-social-login/#github-oauth-configuration">
            Read the docs
          </CustomLink>
        </div>
      }
      placement="top"
      shadow="sm"
      isDisabled={isGithubOAuthEnabled}
      className="w-96"
    >
      <span>
        <Button
          variant="outline"
          className="w-full"
          asChild={isGithubOAuthEnabled}
          disabled={!isGithubOAuthEnabled}
        >
          <a href={githubAuthUrl} className="flex items-center gap-2">
            <Icon icon="simple-icons:github" width={24} />
            Continue with Github
          </a>
        </Button>
      </span>
    </Tooltip>
  </>
);
