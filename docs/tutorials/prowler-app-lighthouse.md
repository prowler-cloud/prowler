# Prowler Lighthouse

Prowler Lighthouse is an AI Cloud Security Analyst chatbot that helps you understand, prioritize, and remediate security findings in your cloud environments. It's designed to provide security expertise for teams without dedicated resources, acting as your 24/7 virtual cloud security analyst.

<img src="../img/lighthouse-intro.png" alt="Prowler Lighthouse">

## How It Works

Prowler Lighthouse uses OpenAI's language models and integrates with your Prowler security findings data.

Here's what's happening behind the scenes:

- The system uses a multi-agent architecture built with [LanggraphJS](https://github.com/langchain-ai/langgraphjs) for LLM logic and [Vercel AI SDK UI](https://sdk.vercel.ai/docs/ai-sdk-ui/overview) for frontend chatbot.
- It uses a ["supervisor" architecture](https://langchain-ai.lang.chat/langgraphjs/tutorials/multi_agent/agent_supervisor/) that interacts with different agents for specialized tasks. For example, `findings_agent` can analyze detected security findings, while `overview_agent` provides a summary of connected cloud accounts.
- The system connects to OpenAI models to understand, fetch the right data, and respond to the user's query.
???+ note
    Lighthouse is tested against `gpt-4o` and `gpt-4o-mini` OpenAI models.
- The supervisor agent is the main contact point. It is what users interact with directly from the chat interface. It coordinates with other agents to answer users' questions comprehensively.

<img src="../img/lighthouse-architecture.png" alt="Lighthouse Architecture">

???+ note
    All agents can only read relevant security data. They cannot modify your data or access sensitive information like configured secrets or tenant details.

## Set up

Getting started with Prowler Lighthouse is easy:

1. Go to the configuration page in your Prowler dashboard.
2. Enter your OpenAI API key.
3. Select your preferred model. The recommended one for best results is `gpt-4o`.
4. (Optional) Add business context to improve response quality and prioritization.

<img src="../img/lighthouse-config.png" alt="Lighthouse Configuration">

### Adding Business Context

The optional business context field lets you provide additional information to help Lighthouse understand your environment and priorities, including:

- Your organization's cloud security goals
- Information about account owners or responsible teams
- Compliance requirements for your organization
- Current security initiatives or focus areas

Better context leads to more relevant responses and prioritization that aligns with your needs.

## Capabilities

Prowler Lighthouse is designed to be your AI security team member, with capabilities including:

### Natural Language Querying

Ask questions in plain English about your security findings. Examples:

- "What are my highest risk findings?"
- "Show me all S3 buckets with public access."
- "What security issues were found in my production accounts?"

<img src="../img/lighthouse-feature1.png" alt="Natural language querying">

### Detailed Remediation Guidance

Get tailored step-by-step instructions for fixing security issues:

- Clear explanations of the problem and its impact
- Commands or console steps to implement fixes
- Alternative approaches with different solutions

<img src="../img/lighthouse-feature2.png" alt="Detailed Remediation">

### Enhanced Context and Analysis

Lighthouse can provide additional context to help you understand the findings:

- Explain security concepts related to findings in simple terms
- Provide risk assessments based on your environment and context
- Connect related findings to show broader security patterns

<img src="../img/lighthouse-config.png" alt="Business Context">

<img src="../img/lighthouse-feature3.png" alt="Contextual Responses">

## Important Notes

Prowler Lighthouse is powerful, but there are limitations:

- **Continuous improvement**: Please report any issues, as the feature may make mistakes or encounter errors, despite extensive testing.
- **Access limitations**: Lighthouse can only access data the logged-in user can view. If you can't see certain information, Lighthouse can't see it either.
- **NextJS session dependence**: If your Prowler application session expires or logs out, Lighthouse will error out. Refresh and log back in to continue.
- **Response quality**: The response quality depends on the selected OpenAI model. For best results, use gpt-4o.

### Getting Help

If you encounter issues with Prowler Lighthouse or have suggestions for improvements, please [reach out through our Slack channel](https://goto.prowler.com/slack).

### What Data Is Shared to OpenAI?

The following API endpoints are accessible to Prowler Lighthouse. Data from the following API endpoints could be shared with OpenAI depending on the scope of user's query:

#### Accessible API Endpoints

**User Management:**

- List all users - `/api/v1/users`
- Retrieve the current user's information - `/api/v1/users/me`

**Provider Management:**

- List all providers - `/api/v1/providers`
- Retrieve data from a provider - `/api/v1/providers/{id}`

**Scan Management:**

- List all scans - `/api/v1/scans`
- Retrieve data from a specific scan - `/api/v1/scans/{id}`

**Resource Management:**

- List all resources - `/api/v1/resources`
- Retrieve data for a resource - `/api/v1/resources/{id}`

**Findings Management:**

- List all findings - `/api/v1/findings`
- Retrieve data from a specific finding - `/api/v1/findings/{id}`
- Retrieve metadata values from findings - `/api/v1/findings/metadata`

**Overview Data:**

- Get aggregated findings data - `/api/v1/overviews/findings`
- Get findings data by severity - `/api/v1/overviews/findings_severity`
- Get aggregated provider data - `/api/v1/overviews/providers`
- Get findings data by service - `/api/v1/overviews/services`

**Compliance Management:**

- List compliance overviews for a scan - `/api/v1/compliance-overviews`
- Retrieve data from a specific compliance overview - `/api/v1/compliance-overviews/{id}`

#### Excluded API Endpoints

Not all Prowler API endpoints are integrated with Lighthouse. They are intentionally excluded for the following reasons:

- OpenAI/other LLM providers shouldn't have access to sensitive data (like fetching provider secrets and other sensitive config)
- Users queries don't need responses from those API endpoints (ex: tasks, tenant details, downloading zip file, etc.)

**Excluded Endpoints:**

**User Management:**

- List specific users information - `/api/v1/users/{id}`
- List user memberships - `/api/v1/users/{user_pk}/memberships`
- Retrieve membership data from the user - `/api/v1/users/{user_pk}/memberships/{id}`

**Tenant Management:**

- List all tenants - `/api/v1/tenants`
- Retrieve data from a tenant - `/api/v1/tenants/{id}`
- List tenant memberships - `/api/v1/tenants/{tenant_pk}/memberships`
- List all invitations - `/api/v1/tenants/invitations`
- Retrieve data from tenant invitation - `/api/v1/tenants/invitations/{id}`

**Security and Configuration:**

- List all secrets - `/api/v1/providers/secrets`
- Retrieve data from a secret - `/api/v1/providers/secrets/{id}`
- List all provider groups - `/api/v1/provider-groups`
- Retrieve data from a provider group - `/api/v1/provider-groups/{id}`

**Reports and Tasks:**

- Download zip report - `/api/v1/scans/{v1}/report`
- List all tasks - `/api/v1/tasks`
- Retrieve data from a specific task - `/api/v1/tasks/{id}`

**Lighthouse Configuration:**

- List OpenAI configuration - `/api/v1/lighthouse-config`
- Retrieve OpenAI key and configuration - `/api/v1/lighthouse-config/{id}`

???+ note
    Agents only have access to hit GET endpoints. They don't have access to other HTTP methods.

## FAQs

**1. Why only OpenAI models?**

During feature development, we evaluated other LLM models.

- **Claude AI** - Claude models have [tier-based ratelimits](https://docs.anthropic.com/en/api/rate-limits#requirements-to-advance-tier). For Lighthouse to answer slightly complex questions, there are a handful of API calls to the LLM provider within few seconds. With Claude's tiering system, users must purchase $400 credits or convert their subscription to monthly invoicing after talking to their sales team. This pricing may not suit all Prowler users.
- **Gemini Models** - Gemini lacks a solid tool calling feature like OpenAI. It calls functions recursively until exceeding limits. Gemini-2.5-Pro-Experimental is better than previous models regarding tool calling and responding, but it's still experimental.
- **Deepseek V3** - Doesn't support system prompt messages.

**2. Why a multi-agent supervisor model?**

Context windows are limited. While demo data fits inside the context window, querying real-world data often exceeds it. A multi-agent architecture is used so different agents fetch different sizes of data and respond with the minimum required data to the supervisor. This spreads the context window usage across agents.

**3. Is my security data shared with OpenAI?**

Minimal data is shared to generate useful responses. Agents can access security findings and remediation details when needed. Provider secrets are protected by design and cannot be read. The Lighthouse key is only accessible to our NextJS server and is never sent to LLMs. Resource metadata (names, tags, account/project IDs, etc) may be shared with OpenAI based on your query requirements.

**4. Can the Lighthouse change my cloud environment?**

No. The agent doesn't have the tools to make the changes, even if the configured cloud provider API keys contain permissions to modify resources.
