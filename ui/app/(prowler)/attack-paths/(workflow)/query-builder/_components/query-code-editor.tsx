"use client";

import {
  HighlightStyle,
  StreamLanguage,
  syntaxHighlighting,
} from "@codemirror/language";
import { tags } from "@lezer/highlight";
import CodeMirror, {
  EditorView,
  highlightActiveLineGutter,
  lineNumbers,
  placeholder as codeEditorPlaceholder,
} from "@uiw/react-codemirror";
import { useTheme } from "next-themes";
import { type HTMLAttributes } from "react";

import { Badge } from "@/components/shadcn";
import { cn } from "@/lib/utils";

const OPEN_CYPHER_KEYWORDS = new Set([
  "all",
  "and",
  "as",
  "asc",
  "ascending",
  "by",
  "call",
  "case",
  "contains",
  "create",
  "delete",
  "desc",
  "descending",
  "detach",
  "distinct",
  "else",
  "end",
  "exists",
  "false",
  "in",
  "is",
  "limit",
  "match",
  "merge",
  "not",
  "null",
  "optional",
  "or",
  "order",
  "remove",
  "return",
  "set",
  "skip",
  "then",
  "true",
  "unwind",
  "where",
  "with",
  "xor",
  "yield",
]);

const OPEN_CYPHER_FUNCTIONS = new Set([
  "collect",
  "coalesce",
  "count",
  "exists",
  "head",
  "id",
  "keys",
  "labels",
  "last",
  "length",
  "nodes",
  "properties",
  "range",
  "reduce",
  "relationships",
  "size",
  "startnode",
  "sum",
  "tail",
  "timestamp",
  "tolower",
  "toupper",
  "trim",
  "type",
]);

interface OpenCypherParserState {
  inBlockComment: boolean;
  inString: "'" | '"' | null;
}

const openCypherLanguage = StreamLanguage.define<OpenCypherParserState>({
  startState() {
    return {
      inBlockComment: false,
      inString: null,
    };
  },
  token(stream, state) {
    if (state.inBlockComment) {
      while (!stream.eol()) {
        if (stream.match("*/")) {
          state.inBlockComment = false;
          break;
        }
        stream.next();
      }

      return "comment";
    }

    if (state.inString) {
      let escaped = false;

      while (!stream.eol()) {
        const next = stream.next();

        if (escaped) {
          escaped = false;
          continue;
        }

        if (next === "\\") {
          escaped = true;
          continue;
        }

        if (next === state.inString) {
          state.inString = null;
          break;
        }
      }

      // OpenCypher only supports single-line strings — reset at EOL so an
      // unclosed quote does not bleed into subsequent lines.
      if (stream.eol()) {
        state.inString = null;
      }

      return "string";
    }

    if (stream.eatSpace()) {
      return null;
    }

    if (stream.match("//")) {
      stream.skipToEnd();
      return "comment";
    }

    if (stream.match("/*")) {
      state.inBlockComment = true;
      return "comment";
    }

    const quote = stream.peek();
    if (quote === "'" || quote === '"') {
      state.inString = quote;
      stream.next();
      return "string";
    }

    if (stream.match(/\$[A-Za-z_][\w]*/)) {
      return "variableName";
    }

    if (stream.match(/:[A-Za-z_][\w]*/)) {
      return "typeName";
    }

    if (stream.match(/[()[\]{},.;]/)) {
      return "punctuation";
    }

    if (stream.match(/[<>!=~|&+\-/*%^]+/)) {
      return "operator";
    }

    if (stream.match(/\d+(?:\.\d+)?/)) {
      return "number";
    }

    if (stream.match(/[A-Za-z_][\w]*/)) {
      const currentValue = stream.current();
      const normalizedValue = currentValue.toLowerCase();

      if (OPEN_CYPHER_KEYWORDS.has(normalizedValue)) {
        return "keyword";
      }

      if (
        OPEN_CYPHER_FUNCTIONS.has(normalizedValue) &&
        stream.match(/\s*(?=\()/, false)
      ) {
        return "function";
      }

      return "variableName";
    }

    stream.next();
    return null;
  },
});

const lightHighlightStyle = HighlightStyle.define([
  { tag: tags.keyword, color: "#0550ae", fontWeight: "600" },
  { tag: tags.string, color: "#0a3069" },
  { tag: tags.number, color: "#8250df" },
  { tag: [tags.typeName, tags.className], color: "#953800" },
  { tag: [tags.variableName, tags.propertyName], color: "#24292f" },
  { tag: tags.function(tags.variableName), color: "#8250df" },
  { tag: tags.operator, color: "#57606a" },
  { tag: tags.comment, color: "#6e7781", fontStyle: "italic" },
  { tag: tags.punctuation, color: "#57606a" },
]);

const darkHighlightStyle = HighlightStyle.define([
  { tag: tags.keyword, color: "#79c0ff", fontWeight: "600" },
  { tag: tags.string, color: "#a5d6ff" },
  { tag: tags.number, color: "#d2a8ff" },
  { tag: [tags.typeName, tags.className], color: "#ffa657" },
  { tag: [tags.variableName, tags.propertyName], color: "#e6edf3" },
  { tag: tags.function(tags.variableName), color: "#d2a8ff" },
  { tag: tags.operator, color: "#8b949e" },
  { tag: tags.comment, color: "#8b949e", fontStyle: "italic" },
  { tag: tags.punctuation, color: "#8b949e" },
]);

const MONO_FONT =
  'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';

const baseThemeRules: Record<string, Record<string, string>> = {
  "&": {
    backgroundColor: "transparent",
    color: "var(--text-neutral-primary)",
    fontFamily: MONO_FONT,
    fontSize: "12px",
  },
  "&.cm-focused": {
    outline: "none",
  },
  ".cm-scroller": {
    minHeight: "320px",
    overflow: "auto",
    fontFamily: MONO_FONT,
    lineHeight: "1.5rem",
  },
  ".cm-content": {
    padding: "16px",
    caretColor: "var(--text-neutral-primary)",
  },
  ".cm-line": {
    padding: "0 0 0 8px",
  },
  ".cm-gutters": {
    backgroundColor: "var(--bg-neutral-secondary)",
    color: "var(--text-neutral-tertiary)",
    borderRight: "1px solid var(--border-neutral-secondary)",
    minWidth: "44px",
  },
  ".cm-lineNumbers .cm-gutterElement": {
    padding: "0 10px 0 12px",
  },
  ".cm-activeLineGutter": {
    backgroundColor: "var(--bg-neutral-secondary)",
    color: "var(--text-neutral-secondary)",
  },
  ".cm-activeLine": {
    backgroundColor: "transparent",
  },
  ".cm-cursor, .cm-dropCursor": {
    borderLeftColor: "var(--text-neutral-primary)",
  },
  ".cm-placeholder": {
    color: "var(--text-neutral-tertiary)",
  },
};

const LIGHT_SELECTION_BG = "rgba(9, 105, 218, 0.18)";
const DARK_SELECTION_BG = "rgba(121, 192, 255, 0.18)";

const lightTheme = EditorView.theme(
  {
    ...baseThemeRules,
    ".cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection":
      { backgroundColor: LIGHT_SELECTION_BG },
  },
  { dark: false },
);

const darkTheme = EditorView.theme(
  {
    ...baseThemeRules,
    ".cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection":
      { backgroundColor: DARK_SELECTION_BG },
  },
  { dark: true },
);

interface QueryCodeEditorProps
  extends Omit<HTMLAttributes<HTMLDivElement>, "onChange"> {
  ariaLabel: string;
  language?: "openCypher";
  value: string;
  placeholder?: string;
  invalid?: boolean;
  requirementBadge?: string;
  onChange: (value: string) => void;
  onBlur?: () => void;
}

export const QueryCodeEditor = ({
  id,
  className,
  ariaLabel,
  language = "openCypher",
  value,
  placeholder,
  invalid = false,
  requirementBadge,
  onChange,
  onBlur,
  ...props
}: QueryCodeEditorProps) => {
  const { resolvedTheme } = useTheme();
  const isDarkMode = resolvedTheme === "dark";
  const editorTheme = isDarkMode ? darkTheme : lightTheme;
  const editorHighlightStyle = isDarkMode
    ? darkHighlightStyle
    : lightHighlightStyle;

  return (
    <div
      data-testid="query-code-editor"
      data-language={language}
      className={cn(
        "border-border-neutral-secondary bg-bg-neutral-primary overflow-hidden rounded-xl border",
        invalid && "border-border-error-primary",
        className,
      )}
      {...props}
    >
      <div className="border-border-neutral-secondary bg-bg-neutral-secondary flex items-center justify-between border-b px-4 py-2">
        <span className="text-text-neutral-secondary text-xs font-medium">
          {ariaLabel}
        </span>
        {requirementBadge ? (
          <Badge
            variant="tag"
            className="text-text-neutral-secondary border-border-neutral-secondary bg-bg-neutral-primary px-2 py-0 text-[11px]"
          >
            {requirementBadge}
          </Badge>
        ) : null}
      </div>

      <CodeMirror
        value={value}
        theme={editorTheme}
        basicSetup={{
          foldGutter: false,
          highlightActiveLine: false,
          highlightActiveLineGutter: false,
          searchKeymap: false,
        }}
        editable={true}
        onChange={onChange}
        extensions={[
          lineNumbers(),
          highlightActiveLineGutter(),
          EditorView.lineWrapping,
          codeEditorPlaceholder(placeholder ?? ""),
          openCypherLanguage,
          syntaxHighlighting(editorHighlightStyle),
          EditorView.contentAttributes.of({
            id: id ?? "",
            "aria-label": ariaLabel,
            "aria-invalid": invalid ? "true" : "false",
          }),
          EditorView.editorAttributes.of({
            class: "minimal-scrollbar",
          }),
          EditorView.domEventHandlers({
            blur: () => {
              onBlur?.();
              return false;
            },
          }),
        ]}
      />
    </div>
  );
};
