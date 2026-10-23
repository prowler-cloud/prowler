// Entry point for the coderabbit-notify workflow. Two subcommands:
//   decide  reads the pull_request_review event, writes step outputs and a message file
//   send    posts the message file to Slack as a direct message to the author
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildLauncherUrl, buildSlackMessage, decide, resolveSlackUser } from "./lib.mjs";

const here = new URL(".", import.meta.url).pathname;
const messagePath = join(process.env.RUNNER_TEMP ?? here, "coderabbit-notify-message.json");

const command = process.argv[2];
if (command === "decide") await runDecide();
else if (command === "send") await runSend();
else fail(`unknown command: ${command}`);

async function runDecide() {
  const event = JSON.parse(readFileSync(requireEnv("GITHUB_EVENT_PATH"), "utf8"));
  const review = event.review;
  const pullRequest = event.pull_request;
  const repo = event.repository.full_name;
  const slackUsers = JSON.parse(readFileSync(join(here, "slack-users.json"), "utf8"));

  const headSha = await fetchHeadSha(repo, pullRequest.number);
  const slackUserId = resolveSlackUser(slackUsers, pullRequest.user?.login);
  const decision = decide({ review, pullRequest, headSha, slackUserId });

  console.log(`decision: notify=${decision.notify} (${decision.reason})`);
  setOutput("notify", String(decision.notify));
  setOutput("publication_id", decision.publicationId ?? "none");

  if (!decision.notify) return;

  const launcherUrl = buildLauncherUrl(process.env.LAUNCHER_URL, {
    repo,
    pr: pullRequest.number,
    sha: decision.commitId,
  });
  const message = buildSlackMessage({ pullRequest, repo, parsed: decision, launcherUrl });
  writeFileSync(messagePath, JSON.stringify({ slackUserId, message }, null, 2));
}

async function runSend() {
  const token = requireEnv("SLACK_BOT_TOKEN");
  const { slackUserId, message } = JSON.parse(readFileSync(messagePath, "utf8"));

  const opened = await slack(token, "conversations.open", { users: slackUserId });
  const channel = opened.channel?.id;
  if (!channel) fail("conversations.open returned no channel id");

  const posted = await slack(token, "chat.postMessage", { channel, ...message });
  console.log(`sent Slack message ${posted.ts} to ${slackUserId}`);
}

async function fetchHeadSha(repo, number) {
  const token = process.env.GH_TOKEN;
  if (!token) {
    console.log("GH_TOKEN is not set, skipping the head sha check");
    return null;
  }
  const response = await fetch(`https://api.github.com/repos/${repo}/pulls/${number}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!response.ok) fail(`GitHub API ${response.status} while reading PR ${number}`);
  const pr = await response.json();
  return pr.head?.sha ?? null;
}

async function slack(token, method, payload) {
  const response = await fetch(`https://slack.com/api/${method}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!data.ok) fail(`Slack ${method} failed: ${data.error ?? response.status}`);
  return data;
}

function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  else console.log(`output ${name}=${value}`);
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) fail(`${name} is not set`);
  return value;
}

function fail(message) {
  console.error(`::error::${message}`);
  process.exit(1);
}
