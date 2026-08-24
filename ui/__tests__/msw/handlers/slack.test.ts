/**
 * The Slack double's own writes, driven over HTTP instead of through the page.
 * A connection check is the one call that edits the install it answers about,
 * and which channels it stamps as confirmed decides what every later read says
 * — including states the page cannot navigate to, so a page test cannot reach
 * them. A double that serves a state the API cannot produce lets a UI test
 * prove copy no deployment can show.
 */

import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { handlersForSlack } from "./slack";
import {
  SLACK_INTEGRATION_ID,
  SLACK_NOT_IN_CHANNEL_CODE,
  SLACK_PRIVATE_CHANNEL,
  SLACK_PUBLIC_CHANNEL,
  SLACK_TOKEN_REVOKED_CODE,
  unconfirmedChannelsSlackFixture,
} from "./slack.fixtures";
import type { SlackConnectionFixture } from "./slack.fixtures";

const API = process.env.UI_API_BASE_URL;

/** The channel as the `configuration` serializes it (contract, OAuth and reads). */
interface ChannelBody {
  id: string;
  confirmation_sent_at: string | null;
}

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/**
 * A check as the UI runs one: queue it, poll the task that carries the outcome,
 * then read the install back — the poll is what writes, so the read has to
 * follow it.
 */
const runConnectionCheck = async (connection: SlackConnectionFixture) => {
  server.use(
    ...handlersForSlack(
      unconfirmedChannelsSlackFixture(
        [SLACK_PUBLIC_CHANNEL, SLACK_PRIVATE_CHANNEL],
        { connection },
      ),
    ),
  );

  const queued = await fetch(
    `${API}/integrations/${SLACK_INTEGRATION_ID}/connection`,
    { method: "POST" },
  );
  expect(queued.status).toBe(202);
  const { data: task } = (await queued.json()) as { data: { id: string } };

  const polled = await fetch(`${API}/tasks/${task.id}`);
  expect(polled.status).toBe(200);

  const listed = await fetch(
    `${API}/integrations?filter[integration_type]=slack`,
  );
  const { data } = (await listed.json()) as {
    data: {
      attributes: {
        connected: boolean | null;
        configuration: { channels: ChannelBody[] };
      };
    }[];
  };

  const { connected: recorded, configuration } = data[0].attributes;
  return {
    connected: recorded,
    confirmedAt: new Map(
      configuration.channels.map((channel) => [
        channel.id,
        channel.confirmation_sent_at,
      ]),
    ),
  };
};

describe("the Slack double's connection check", () => {
  it("confirms no channel at all when the failure is about the workspace", async () => {
    // Given/When — the stored grant is gone, which `auth.test` finds out before
    // the per-channel loop starts, so the failure names no channel.
    const { connected, confirmedAt } = await runConnectionCheck({
      connected: false,
      error: SLACK_TOKEN_REVOKED_CODE,
    });

    // Then — nothing was posted, so nothing is confirmed: a record claiming
    // otherwise would be a state the API cannot produce.
    expect(connected).toBe(false);
    expect(confirmedAt.get(SLACK_PUBLIC_CHANNEL.id)).toBeNull();
    expect(confirmedAt.get(SLACK_PRIVATE_CHANNEL.id)).toBeNull();
  });

  it("confirms every channel but the one a channel-level failure names", async () => {
    // Given/When — the token is fine and Slack refuses one channel of the set.
    const { connected, confirmedAt } = await runConnectionCheck({
      connected: false,
      error: SLACK_NOT_IN_CHANNEL_CODE,
      failedChannelId: SLACK_PRIVATE_CHANNEL.id,
    });

    // Then — the refused channel is the retry's remaining work, the other one
    // is done.
    expect(connected).toBe(false);
    expect(confirmedAt.get(SLACK_PUBLIC_CHANNEL.id)).not.toBeNull();
    expect(confirmedAt.get(SLACK_PRIVATE_CHANNEL.id)).toBeNull();
  });

  it("confirms the whole set when the check succeeds", async () => {
    // Given/When
    const { connected, confirmedAt } = await runConnectionCheck({
      connected: true,
      error: null,
    });

    // Then
    expect(connected).toBe(true);
    expect(confirmedAt.get(SLACK_PUBLIC_CHANNEL.id)).not.toBeNull();
    expect(confirmedAt.get(SLACK_PRIVATE_CHANNEL.id)).not.toBeNull();
  });
});
