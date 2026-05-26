export interface ScanErrorDetails {
  type: string;
  messages: string[];
  module?: string;
  copyValue: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function getString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : undefined;
}

function getStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];

  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter((item) => item !== "");
}

export function getScanErrorDetails(
  taskResponse: unknown,
): ScanErrorDetails | null {
  if (!isRecord(taskResponse) || !isRecord(taskResponse.data)) return null;
  if (!isRecord(taskResponse.data.attributes)) return null;
  if (!isRecord(taskResponse.data.attributes.result)) return null;

  const result = taskResponse.data.attributes.result;
  const type = getString(result.exc_type) ?? "-";
  const messages = getStringList(result.exc_message);
  const module = getString(result.exc_module);

  if (type === "-" && messages.length === 0 && !module) return null;

  const errorText = messages.length > 0 ? messages.join("\n") : "-";

  return {
    type,
    messages: messages.length > 0 ? messages : ["-"],
    module,
    copyValue: `ErrorType: ${type}\nError: ${errorText}`,
  };
}
