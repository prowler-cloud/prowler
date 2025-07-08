# Extending Prowler Lighthouse

This guide helps developers customize and extend Prowler Lighthouse by adding or modifying AI agents.

## Understanding AI Agents

AI agents combine Large Language Models (LLMs) with specialized tools that provide environmental context. These tools can include API calls, system command execution, or any function-wrapped capability.

### Types of AI Agents

AI agents fall into two main categories:

- **Autonomous Agents**: Freely chooses from available tools to complete tasks, adapting their approach based on context. They decide which tools to use and when.
- **Workflow Agents**: Follows structured paths with predefined logic. They execute specific tool sequences and can include conditional logic.

Prowler Lighthouse is an autonomous agent - selecting the right tool(s) based on the users query.

???+ note
    To learn more about AI agents, read [Anthropic's blog post on building effective agents](https://www.anthropic.com/engineering/building-effective-agents).

### LLM Dependency

The autonomous nature of agents depends on the underlying LLM. Autonomous agents using identical system prompts and tools but powered by different LLM providers might approach user queries differently. Agent with one LLM might solve a problem efficiently, while with another it might take a different route or fail entirely.

After evaluating multiple LLM providers (OpenAI, Gemini, Claude, LLama) based on tool calling features and response accuracy, we recommend using the `gpt-4o` model.

## Prowler Lighthouse Architecture

Prowler Lighthouse uses a multi-agent architecture orchestrated by the [Langgraph-Supervisor](https://www.npmjs.com/package/@langchain/langgraph-supervisor) library.

### Architecture Components

<img src="../../tutorials/img/lighthouse-architecture.png" alt="Prowler Lighthouse architecture">

Prowler Lighthouse integrates with the NextJS application:

- The [Langgraph-Supervisor](https://www.npmjs.com/package/@langchain/langgraph-supervisor) library integrates directly with NextJS
- The system uses the authenticated user session to interact with the Prowler API server
- Agents only access data the current user is authorized to view
- Session management operates automatically, ensuring Role-Based Access Control (RBAC) is maintained

## Available Prowler AI Agents

The following specialized AI agents are available in Prowler:

### Agent Overview

- **provider_agent**: Fetches information about cloud providers connected to Prowler
- **user_info_agent**: Retrieves information about Prowler users
- **scans_agent**: Fetches information about Prowler scans
- **compliance_agent**: Retrieves compliance overviews across scans
- **findings_agent**: Fetches information about individual findings across scans
- **overview_agent**: Retrieves overview information (providers, findings by status and severity, etc.)

## How to Add New Capabilities

### Updating the Supervisor Prompt

The supervisor agent controls system behavior, tone, and capabilities. You can find the supervisor prompt at: [https://github.com/prowler-cloud/prowler/blob/master/ui/lib/lighthouse/prompts.ts](https://github.com/prowler-cloud/prowler/blob/master/ui/lib/lighthouse/prompts.ts)

#### Supervisor Prompt Modifications

Modifying the supervisor prompt allows you to:

- Change personality or response style
- Add new high-level capabilities
- Modify task delegation to specialized agents
- Set up guardrails (query types to answer or decline)

???+ note
    The supervisor agent should not have its own tools. This design keeps the system modular and maintainable.

### How to Create New Specialized Agents

The supervisor agent and all specialized agents are defined in the `route.ts` file. The supervisor agent uses [langgraph-supervisor](https://www.npmjs.com/package/@langchain/langgraph-supervisor), while other agents use the prebuilt [create-react-agent](https://langchain-ai.github.io/langgraphjs/how-tos/create-react-agent/).

To add new capabilities or all Lighthouse to interact with other APIs, create additional specialized agents:

1. First determine what the new agent would do. Create a detailed prompt defining the agent's purpose and capabilities. You can see an example from [here](https://github.com/prowler-cloud/prowler/blob/master/ui/lib/lighthouse/prompts.ts#L359-L385).
???+ note
    Ensure that the new agent's capabilities don't collide with existing agents. For example, if there's already a *findings_agent* that talks to findings APIs don't create a new agent to do the same.

2. Create necessary tools for the agents to access specific data or perform actions. A tool is a specialized function that extends the capabilities of LLM by allowing it to access external data or APIs. A tool is triggered by LLM based on the description of the tool and the user's query.
For example, the description of `getScanTool` is "Fetches detailed information about a specific scan by its ID." If the description doesn't convey what the tool is capable of doing, LLM will not invoke the function. If the description of `getScanTool` was set to something random or not set at all, LLM will not answer queries like "Give me the critical issues from the scan ID xxxxxxxxxxxxxxx"
???+ note
    Ensure that one tool is added to one agent only. Adding tools is optional. There can be agents with no tools at all.

3. Use the `createReactAgent` function to define a new agent. For example, the rolesAgent name is "roles_agent" and has access to call tools "*getRolesTool*" and "*getRoleTool*"
```js
const rolesAgent = createReactAgent({
  llm: llm,
  tools: [getRolesTool, getRoleTool],
  name: "roles_agent",
  prompt: rolesAgentPrompt,
});
```

4. Create a detailed prompt defining the agent's purpose and capabilities.

5. Add the new agent to the available agents list:
```js
const agents = [
  userInfoAgent,
  providerAgent,
  overviewAgent,
  scansAgent,
  complianceAgent,
  findingsAgent,
  rolesAgent,  // New agent added here
];
// Create supervisor workflow
const workflow = createSupervisor({
  agents: agents,
  llm: supervisorllm,
  prompt: supervisorPrompt,
  outputMode: "last_message",
});
```

6. Update the supervisor's system prompt to summarize the new agent's capabilities.

### Best Practices for Agent Development

When developing new agents or capabilities:

- **Clear Responsibility Boundaries**: Each agent should have a defined purpose with minimal overlap. No two agents should access the same tools or different tools accessing the same Prowler APIs.
- **Minimal Data Access**: Agents should only request the data they need, keeping requests specific to minimize context window usage, cost, and response time.
- **Thorough Prompting:** Ensure agent prompts include clear instructions about:
    - The agent's purpose and limitations
    - How to use its tools
    - How to format responses for the supervisor
    - Error handling procedures (Optional)
- **Security Considerations:** Agents should never modify data or access sensitive information like secrets or credentials.
- **Testing:** Thoroughly test new agents with various queries before deploying to production.
