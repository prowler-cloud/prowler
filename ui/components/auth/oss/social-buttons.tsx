import { Button } from "@heroui/button";
import { Tooltip } from "@heroui/tooltip";
import { Icon } from "@iconify/react";

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
          startContent={<Icon icon="flat-color-icons:google" width={24} />}
          variant="bordered"
          className="w-full"
          as="a"
          href={googleAuthUrl}
          isDisabled={!isGoogleOAuthEnabled}
        >
          Continue with Google
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
          startContent={
            <Icon className="text-default-500" icon="fe:github" width={24} />
          }
          variant="bordered"
          className="w-full"
          as="a"
          href={githubAuthUrl}
          isDisabled={!isGithubOAuthEnabled}
        >
          Continue with Github
        </Button>
      </span>
    </Tooltip>
  </>
);
