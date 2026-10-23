// Pure helpers for the CodeRabbit → Slack notification. No I/O here so they stay testable.

export const CODERABBIT_LOGIN = "coderabbitai[bot]";

const ACTIONABLE_RE = /\*\*Actionable comments posted: (\d+)\*\*/;
const PUBLICATION_RE = /coderabbit-review-publication[^>]*\bpublication=([0-9a-f-]{36})/;
const ATTEMPT_RE = /coderabbit-review-publication[^>]*\battempt=([0-9a-f-]{36})/;
// owner/name where neither segment starts with a dot, so "../x" never builds a URL.
const REPO_RE = /^[\w-][\w.-]*\/[\w-][\w.-]*$/;

/** Read what the notification needs out of a CodeRabbit review object. */
export function parseReview(review) {
  const body = review?.body ?? "";
  const actionableMatch = ACTIONABLE_RE.exec(body);
  return {
    isCodeRabbit: review?.user?.login === CODERABBIT_LOGIN,
    actionable: actionableMatch ? Number(actionableMatch[1]) : 0,
    publicationId: PUBLICATION_RE.exec(body)?.[1] ?? null,
    attemptId: ATTEMPT_RE.exec(body)?.[1] ?? null,
    commitId: review?.commit_id ?? null,
    state: review?.state ?? null,
  };
}

/** Decide whether a review deserves a notification. Returns a reason when it does not. */
export function decide({ review, pullRequest, headSha, slackUserId }) {
  const parsed = parseReview(review);
  if (!parsed.isCodeRabbit) return skip("review is not from CodeRabbit", parsed);
  if (parsed.actionable === 0) return skip("review has no actionable comments", parsed);
  if (!parsed.publicationId) return skip("review body has no publication id", parsed);
  if (headSha && parsed.commitId !== headSha) {
    return skip(`reviewed commit ${short(parsed.commitId)} is not the PR head ${short(headSha)}`, parsed);
  }
  if (pullRequest?.state && pullRequest.state !== "open") return skip("pull request is not open", parsed);
  if (!slackUserId) return skip(`author ${pullRequest?.user?.login ?? "?"} is not mapped to Slack`, parsed);
  return { notify: true, reason: "actionable review on the PR head", ...parsed };
}

function skip(reason, parsed) {
  return { notify: false, reason, ...parsed };
}

/** Look up the Slack user id for a GitHub login in the committed map. */
export function resolveSlackUser(map, login) {
  if (!login) return null;
  const id = map?.[login] ?? map?.[login.toLowerCase()] ?? null;
  return typeof id === "string" && id.startsWith("U") ? id : null;
}

/** Build the launcher URL the Slack button opens. Returns null when no launcher is configured. */
export function buildLauncherUrl(launcherBase, { repo, pr, sha }) {
  if (!launcherBase) return null;
  if (!REPO_RE.test(repo)) throw new Error(`invalid repo slug: ${repo}`);
  const url = new URL(launcherBase);
  url.searchParams.set("repo", repo);
  url.searchParams.set("pr", String(pr));
  url.searchParams.set("sha", sha);
  return url.toString();
}

/** Build the Slack chat.postMessage payload (text fallback, blocks and metadata). */
export function buildSlackMessage({ pullRequest, repo, parsed, launcherUrl }) {
  const count = parsed.actionable;
  const noun = count === 1 ? "actionable comment" : "actionable comments";
  const title = `${pullRequest.title} · ${repo}#${pullRequest.number}`;
  const summary = `CodeRabbit left ${count} ${noun} on ${short(parsed.commitId)}.`;
  const cta = launcherUrl
    ? "Open a local agent to assess the feedback and address the relevant findings."
    : "Run `/address-review " + `${pullRequest.number} ${parsed.commitId}` + "` in your local agent to assess the feedback.";

  const buttons = [];
  if (launcherUrl) {
    buttons.push({
      type: "button",
      style: "primary",
      text: { type: "plain_text", text: "Open local agent" },
      url: launcherUrl,
      action_id: "open_local_agent",
    });
  }
  buttons.push({
    type: "button",
    text: { type: "plain_text", text: "View pull request" },
    url: pullRequest.html_url,
    action_id: "view_pull_request",
  });

  return {
    text: `CodeRabbit review ready: ${title}. ${summary}`,
    blocks: [
      { type: "header", text: { type: "plain_text", text: "CodeRabbit review ready" } },
      { type: "section", text: { type: "mrkdwn", text: `*<${pullRequest.html_url}|${escapeMrkdwn(title)}>*\n${summary}\n${cta}` } },
      { type: "actions", elements: buttons },
    ],
    metadata: {
      event_type: "coderabbit_review_ready",
      event_payload: {
        publication_id: parsed.publicationId,
        repo,
        pr: pullRequest.number,
        sha: parsed.commitId,
      },
    },
  };
}

function short(sha) {
  return typeof sha === "string" ? sha.slice(0, 7) : "?";
}

function escapeMrkdwn(text) {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
