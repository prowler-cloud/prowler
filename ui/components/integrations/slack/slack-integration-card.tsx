import { SettingsIcon } from "lucide-react";
import Link from "next/link";

import { SlackIcon } from "@/components/icons/services/IconServices";
import { Button, Card, CardContent, CardHeader } from "@/components/shadcn";
import { CustomLink } from "@/components/shadcn/custom/custom-link";

// Placeholder slug: the docs slice writes the page and confirms it.
const SLACK_DOCS_URL =
  "https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-slack-integration/";

export const SlackIntegrationCard = () => {
  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <SlackIcon size={40} />
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                Slack
              </h4>
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center">
                <p className="text-xs text-nowrap text-gray-500 dark:text-gray-300">
                  Send Prowler messages to your Slack workspace.
                </p>
                <CustomLink
                  href={SLACK_DOCS_URL}
                  aria-label="Learn more about Slack integration"
                  size="xs"
                >
                  Learn more
                </CustomLink>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <Button asChild size="sm">
              <Link href="/integrations/slack">
                <SettingsIcon size={14} />
                Manage
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Connect a Slack workspace and pick the channel Prowler posts to, so
          your team gets security updates where it already works.
        </p>
      </CardContent>
    </Card>
  );
};
