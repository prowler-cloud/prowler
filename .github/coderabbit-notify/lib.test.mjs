import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { buildLauncherUrl, buildSlackMessage, decide, parseReview, resolveSlackUser } from "./lib.mjs";

const fixtures = new URL("./fixtures/", import.meta.url);
const reviews = JSON.parse(readFileSync(new URL("reviews-13093.json", fixtures), "utf8"));
// The recorded PR is merged by now; the decision tests need it as it was when CodeRabbit reviewed it.
const pullRequest = { ...JSON.parse(readFileSync(new URL("pull-13093.json", fixtures), "utf8")), state: "open" };
const REPO = "prowler-cloud/prowler";

const withFindings = reviews.filter((r) => r.state === "CHANGES_REQUESTED");
const empty = reviews.filter((r) => r.state !== "CHANGES_REQUESTED");
const latest = withFindings[1];

test("fixtures hold real reviews of both kinds", () => {
  assert.equal(withFindings.length, 2);
  assert.ok(empty.length >= 2);
});

test("parseReview reads the actionable count, commit and publication id", () => {
  const parsed = parseReview(latest);
  assert.equal(parsed.isCodeRabbit, true);
  assert.equal(parsed.actionable, 2);
  assert.equal(parsed.commitId, "0c9515a2736a8d1ff1ea5577dcc7db6250834a41");
  assert.match(parsed.publicationId, /^[0-9a-f-]{36}$/);
  assert.match(parsed.attemptId, /^[0-9a-f-]{36}$/);
  assert.notEqual(parsed.publicationId, parseReview(withFindings[0]).publicationId);
});

test("parseReview treats empty CodeRabbit reviews as zero actionable", () => {
  for (const review of empty) {
    const parsed = parseReview(review);
    assert.equal(parsed.isCodeRabbit, true);
    assert.equal(parsed.actionable, 0);
    assert.equal(parsed.publicationId, null);
  }
});

test("decide notifies for an actionable review on the PR head with a mapped author", () => {
  const decision = decide({ review: latest, pullRequest, headSha: latest.commit_id, slackUserId: "U123" });
  assert.equal(decision.notify, true);
});

test("decide skips empty reviews", () => {
  const decision = decide({ review: empty[0], pullRequest, headSha: empty[0].commit_id, slackUserId: "U123" });
  assert.equal(decision.notify, false);
  assert.match(decision.reason, /no actionable/);
});

test("decide skips a review superseded by a newer commit", () => {
  const decision = decide({ review: withFindings[0], pullRequest, headSha: pullRequest.head.sha, slackUserId: "U123" });
  assert.equal(decision.notify, false);
  assert.match(decision.reason, /not the PR head/);
});

test("decide skips reviews from other users", () => {
  const review = { ...latest, user: { login: "someone" } };
  const decision = decide({ review, pullRequest, headSha: latest.commit_id, slackUserId: "U123" });
  assert.equal(decision.notify, false);
  assert.match(decision.reason, /not from CodeRabbit/);
});

test("decide skips unmapped authors", () => {
  const decision = decide({ review: latest, pullRequest, headSha: latest.commit_id, slackUserId: null });
  assert.equal(decision.notify, false);
  assert.match(decision.reason, /not mapped/);
});

test("decide skips when the PR head could not be read", () => {
  const decision = decide({ review: latest, pullRequest, headSha: null, slackUserId: "U123" });
  assert.equal(decision.notify, false);
  assert.match(decision.reason, /head is unknown/);
});

test("decide skips closed pull requests", () => {
  const closed = { ...pullRequest, state: "closed" };
  const decision = decide({ review: latest, pullRequest: closed, headSha: latest.commit_id, slackUserId: "U123" });
  assert.equal(decision.notify, false);
});

test("resolveSlackUser only accepts member ids", () => {
  const map = { _comment: "ignored", alice: "U0AAA", bob: "not-an-id" };
  assert.equal(resolveSlackUser(map, "alice"), "U0AAA");
  assert.equal(resolveSlackUser(map, "bob"), null);
  assert.equal(resolveSlackUser(map, "_comment"), null);
  assert.equal(resolveSlackUser(map, "nobody"), null);
});

test("buildLauncherUrl encodes the PR context and rejects bad slugs", () => {
  const url = buildLauncherUrl("https://example.test/launch/", { repo: REPO, pr: 13093, sha: latest.commit_id });
  assert.equal(url, `https://example.test/launch/?repo=prowler-cloud%2Fprowler&pr=13093&sha=${latest.commit_id}`);
  assert.equal(buildLauncherUrl("", { repo: REPO, pr: 1, sha: "abc" }), null);
  assert.throws(() => buildLauncherUrl("https://example.test/", { repo: "../x", pr: 1, sha: "abc" }));
});

test("buildSlackMessage carries the count, both buttons and dedup metadata", () => {
  const parsed = parseReview(latest);
  const launcherUrl = buildLauncherUrl("https://example.test/launch/", { repo: REPO, pr: 13093, sha: parsed.commitId });
  const message = buildSlackMessage({ pullRequest, repo: REPO, parsed, launcherUrl });

  assert.match(message.text, /2 actionable comments/);
  assert.match(message.text, /#13093/);
  const buttons = message.blocks.at(-1).elements;
  assert.deepEqual(buttons.map((b) => b.url), [launcherUrl, pullRequest.html_url]);
  assert.ok(buttons.every((b) => b.url.length <= 3000));
  assert.equal(message.metadata.event_payload.publication_id, parsed.publicationId);
});

test("buildSlackMessage without a launcher falls back to the command and one button", () => {
  const parsed = parseReview(latest);
  const message = buildSlackMessage({ pullRequest, repo: REPO, parsed, launcherUrl: null });
  assert.equal(message.blocks.at(-1).elements.length, 1);
  assert.match(message.blocks[1].text.text, /\/address-review 13093 0c9515a2736a8d1ff1ea5577dcc7db6250834a41/);
});
