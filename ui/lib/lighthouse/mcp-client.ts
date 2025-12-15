import type { StructuredTool } from "@langchain/core/tools";
import { MultiServerMCPClient } from "@langchain/mcp-adapters";

import { getAuthContext } from "@/lib/lighthouse/auth-context";

/**
 * MCP Client State
 * Using a class-based singleton for better encapsulation and testability
 */
class MCPClientManager {
  private client: MultiServerMCPClient | null = null;
  private tools: StructuredTool[] = [];
  private available = false;
  private initializationAttempted = false;
  private initializationPromise: Promise<void> | null = null;

  async initialize(): Promise<void> {
    // Already initialized successfully
    if (this.initializationAttempted && this.available) {
      return;
    }

    // Initialization in progress
    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    this.initializationPromise = this.performInitialization();
    return this.initializationPromise;
  }

  private async performInitialization(): Promise<void> {
    this.initializationAttempted = true;

    try {
      const mcpServerUrl = process.env.PROWLER_MCP_SERVER_URL || "";

      this.client = new MultiServerMCPClient({
        additionalToolNamePrefix: "",
        mcpServers: {
          prowler: {
            transport: "http",
            url: mcpServerUrl,
          },
        },
        beforeToolCall: this.handleBeforeToolCall,
      });

      this.tools = await this.client.getTools();
      this.available = true;
    } catch (error) {
      console.error("[MCP Client] Failed to initialize:", error);
      this.reset();
    } finally {
      this.initializationPromise = null;
    }
  }

  /**
   * Injects auth headers for Prowler App tools
   */
  private handleBeforeToolCall = ({
    name,
    args,
  }: {
    serverName: string;
    name: string;
    args?: unknown;
  }) => {
    // Only inject auth for Prowler App tools
    if (!name.startsWith("prowler_app_")) {
      return { args };
    }

    const accessToken = getAuthContext();
    if (!accessToken) {
      return { args };
    }

    return {
      args,
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    };
  };

  getTools(): StructuredTool[] {
    return this.tools;
  }

  getToolsByPattern(pattern: RegExp): StructuredTool[] {
    return this.tools.filter((tool) => pattern.test(tool.name));
  }

  getToolByName(name: string): StructuredTool | undefined {
    return this.tools.find((tool) => tool.name === name);
  }

  getToolsByNames(names: string[]): StructuredTool[] {
    return this.tools.filter((tool) => names.includes(tool.name));
  }

  isAvailable(): boolean {
    return this.available;
  }

  reset(): void {
    this.client = null;
    this.tools = [];
    this.available = false;
    this.initializationAttempted = false;
    this.initializationPromise = null;
  }
}

// Singleton instance
// Using a module-level variable instead of global for better HMR support
let mcpClientManager: MCPClientManager | null = null;

function getManager(): MCPClientManager {
  if (!mcpClientManager) {
    mcpClientManager = new MCPClientManager();
  }
  return mcpClientManager;
}

// Public API - maintains backwards compatibility
export async function initializeMCPClient(): Promise<void> {
  return getManager().initialize();
}

export function getMCPTools(): StructuredTool[] {
  return getManager().getTools();
}

export function getMCPToolsByPattern(namePattern: RegExp): StructuredTool[] {
  return getManager().getToolsByPattern(namePattern);
}

export function getMCPToolByName(name: string): StructuredTool | undefined {
  return getManager().getToolByName(name);
}

export function getMCPToolsByNames(names: string[]): StructuredTool[] {
  return getManager().getToolsByNames(names);
}

export function isMCPAvailable(): boolean {
  return getManager().isAvailable();
}

export function resetMCPClient(): void {
  getManager().reset();
}
