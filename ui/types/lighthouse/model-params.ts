export type ModelParams = {
  maxTokens: number | undefined;
  temperature: number | undefined;
  reasoningEffort: "minimal" | "low" | "medium" | "high" | undefined;
};
