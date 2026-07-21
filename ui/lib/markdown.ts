/**
 * Escapes angle-bracket placeholders like <bucket_name> to HTML entities
 * so they display correctly instead of being interpreted as HTML tags.
 *
 * This processes the text while preserving:
 * - Content inside inline code (backticks)
 * - Content inside code blocks (triple backticks)
 *
 * Shared by the Lighthouse v1 and v2 chat renderers.
 */
export function escapeAngleBracketPlaceholders(text: string): string {
  // HTML tags to preserve (not escape)
  const htmlTags = new Set([
    "div",
    "span",
    "p",
    "a",
    "img",
    "br",
    "hr",
    "ul",
    "ol",
    "li",
    "table",
    "tr",
    "td",
    "th",
    "thead",
    "tbody",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "blockquote",
    "strong",
    "em",
    "b",
    "i",
    "u",
    "s",
    "sub",
    "sup",
    "details",
    "summary",
  ]);

  // Split by code blocks and inline code to preserve them.
  // This regex captures: ```...``` blocks, `...` inline code, and everything else.
  const parts = text.split(/(```[\s\S]*?```|`[^`]+`)/g);

  return parts
    .map((part) => {
      // If it's a code block or inline code, leave it untouched.
      // Shiki/syntax highlighter handles escaping inside code blocks.
      if (part.startsWith("```") || part.startsWith("`")) {
        return part;
      }

      // For regular text outside code, escape placeholders as HTML entities so
      // they render as plain `<bucket_name>` text. Raw HTML parsing is disabled
      // in both chat renderers, so entities are enough — and avoid the code-span
      // styling that wrapping in backticks would force.
      return part.replace(/<([a-zA-Z][a-zA-Z0-9_-]*)>/g, (match, tagName) => {
        if (htmlTags.has(tagName.toLowerCase())) {
          return match;
        }
        return `&lt;${tagName}&gt;`;
      });
    })
    .join("");
}
