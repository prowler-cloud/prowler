"use client";

import { format, isValid, parseISO } from "date-fns";
import { TestTube } from "lucide-react";
import { useState } from "react";

import { testIntegrationConnection } from "@/actions/integrations/integrations";
import { SlackIcon } from "@/components/icons/services/IconServices";
import { IntegrationCardHeader } from "@/components/integrations/shared";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Card,
  CardContent,
  CardHeader,
  useToast,
} from "@/components/shadcn";
import type { IntegrationProps } from "@/types/integrations";

interface SlackIntegrationManagerProps {
  /** At most one exists per tenant (one workspace). */
  integration: IntegrationProps | null;
  authorizeUrl: string | null;
  /** This deployment has no Prowler Slack app, so no install can be started. */
  unavailable: boolean;
  rateLimitMessage: string | null;
  loadError: string | null;
}

export const SlackIntegrationManager = ({
  integration,
  authorizeUrl,
  unavailable,
  rateLimitMessage,
  loadError,
}: SlackIntegrationManagerProps) => {
  const [isTesting, setIsTesting] = useState(false);
  const { toast } = useToast();

  const handleTestConnection = async (id: string) => {
    setIsTesting(true);
    try {
      const result = await testIntegrationConnection(id);

      if (result.success) {
        toast({
          title: "Connection test successful!",
          description:
            result.message || "Prowler can reach your Slack workspace.",
        });
      } else {
        toast({
          variant: "destructive",
          title: "Connection test failed",
          description: result.error || "Failed to reach your Slack workspace.",
        });
      }
    } catch (_error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to test connection. Please try again.",
      });
    } finally {
      setIsTesting(false);
    }
  };

  const configuration = integration?.attributes.configuration;
  const workspaceName = configuration?.team_name;
  // Absent until a channel is chosen, never present-and-null.
  const channelId = configuration?.channel_id ?? null;

  const checkedAt = integration?.attributes.connection_last_checked_at;
  const checkedOn = checkedAt ? parseISO(checkedAt) : null;
  // `format` throws a RangeError on an unreadable value, which would replace
  // the page with the route's error boundary: show nothing instead, as for a
  // connection that was never checked.
  const lastCheckedOn =
    checkedOn && isValid(checkedOn) ? format(checkedOn, "yyyy/MM/dd") : null;

  return (
    <div className="flex flex-col gap-6">
      {rateLimitMessage && (
        <Alert variant="warning">
          <AlertTitle>Slack is busy right now</AlertTitle>
          <AlertDescription>{rateLimitMessage}</AlertDescription>
        </Alert>
      )}

      {loadError && (
        <Alert variant="error">
          <AlertTitle>Could not load your Slack integration</AlertTitle>
          <AlertDescription>{loadError}</AlertDescription>
        </Alert>
      )}

      {/* Replaces the cards, not the whole page: an early return here would
          swallow the rate-limit and load-error notices above. */}
      {unavailable ? (
        <Alert variant="info">
          <AlertTitle>
            Slack is not available in this environment yet
          </AlertTitle>
          <AlertDescription>
            The Prowler Slack app is not configured here, so no workspace can be
            connected. Nothing to do on your side — this page starts working as
            soon as it is.
          </AlertDescription>
        </Alert>
      ) : integration ? (
        <Card variant="base">
          <CardHeader>
            <IntegrationCardHeader
              icon={<SlackIcon size={32} />}
              title={`Connected to ${workspaceName ?? "your Slack workspace"}`}
              subtitle="Prowler posts to this workspace only."
              connectionStatus={{
                connected: integration.attributes.connected,
              }}
            />
          </CardHeader>

          <CardContent className="pt-0">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="text-xs text-gray-500 dark:text-gray-300">
                {lastCheckedOn && (
                  <p>
                    <span className="font-medium">Last checked:</span>{" "}
                    {lastCheckedOn}
                  </p>
                )}
                {!channelId && (
                  <p>
                    Choosing a destination channel is the next step — the
                    connection is checked against it.
                  </p>
                )}
              </div>
              {/* The check posts to the destination channel: the API answers
                  400 when none is recorded yet. */}
              <Button
                size="sm"
                variant="outline"
                disabled={isTesting || !channelId}
                onClick={() => handleTestConnection(integration.id)}
              >
                <TestTube size={14} />
                {isTesting ? "Testing..." : "Test connection"}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card variant="base">
          <CardHeader>
            <IntegrationCardHeader
              icon={<SlackIcon size={32} />}
              title="No workspace connected"
              subtitle="Approve Prowler in Slack to connect a workspace. No tokens to copy."
            />
          </CardHeader>

          <CardContent className="pt-0">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <p className="text-sm text-gray-600 dark:text-gray-300">
                Prowler asks for permission to post messages and to read the
                workspace&apos;s channel list.
              </p>
              {authorizeUrl ? (
                <Button asChild>
                  <a href={authorizeUrl} rel="noopener noreferrer">
                    <SlackIcon size={16} />
                    Add to Slack
                  </a>
                </Button>
              ) : (
                <Button disabled>
                  <SlackIcon size={16} />
                  Add to Slack
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
