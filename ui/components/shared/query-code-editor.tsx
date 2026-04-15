"use client";

import {
  HighlightStyle,
  StreamLanguage,
  syntaxHighlighting,
} from "@codemirror/language";
import { EditorState } from "@codemirror/state";
import { tags } from "@lezer/highlight";
import CodeMirror, {
  EditorView,
  highlightActiveLineGutter,
  lineNumbers,
  placeholder as codeEditorPlaceholder,
} from "@uiw/react-codemirror";
import { Check, Copy } from "lucide-react";
import { useTheme } from "next-themes";
import { type HTMLAttributes, useState } from "react";

import { Badge } from "@/components/shadcn";
import { cn } from "@/lib/utils";

const QUERY_EDITOR_LANGUAGE = {
  OPEN_CYPHER: "openCypher",
  PLAIN_TEXT: "plainText",
} as const;

type QueryEditorLanguage =
  (typeof QUERY_EDITOR_LANGUAGE)[keyof typeof QUERY_EDITOR_LANGUAGE];

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

const LIGHT_SELECTION_BG = "rgba(9, 105, 218, 0.18)";
const DARK_SELECTION_BG = "rgba(121, 192, 255, 0.18)";

function createEditorTheme({
  isDarkMode,
  minHeight,
}: {
  isDarkMode: boolean;
  minHeight: number;
}) {
  return EditorView.theme(
    {
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
        minHeight: `${minHeight}px`,
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
      ".cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection":
        {
          backgroundColor: isDarkMode ? DARK_SELECTION_BG : LIGHT_SELECTION_BG,
        },
    },
    { dark: isDarkMode },
  );
}

interface QueryCodeEditorProps
  extends Omit<HTMLAttributes<HTMLDivElement>, "onChange"> {
  ariaLabel: string;
  language?: QueryEditorLanguage;
  value: string;
  copyValue?: string;
  placeholder?: string;
  invalid?: boolean;
  requirementBadge?: string;
  editable?: boolean;
  minHeight?: number;
  showCopyButton?: boolean;
  onChange: (value: string) => void;
  onBlur?: () => void;
}

export const QueryCodeEditor = ({
  id,
  className,
  ariaLabel,
  language = QUERY_EDITOR_LANGUAGE.OPEN_CYPHER,
  value,
  copyValue,
  placeholder,
  invalid = false,
  requirementBadge,
  editable = true,
  minHeight = 320,
  showCopyButton = false,
  onChange,
  onBlur,
  ...props
}: QueryCodeEditorProps) => {
  const { resolvedTheme } = useTheme();
  const [copied, setCopied] = useState(false);
  const isDarkMode = resolvedTheme === "dark";
  const editorTheme = createEditorTheme({ isDarkMode, minHeight });
  const editorHighlightStyle = isDarkMode
    ? darkHighlightStyle
    : lightHighlightStyle;

  const extensions = [
    lineNumbers(),
    highlightActiveLineGutter(),
    EditorView.lineWrapping,
    codeEditorPlaceholder(placeholder ?? ""),
    EditorView.contentAttributes.of({
      id: id ?? "",
      "aria-label": ariaLabel,
      "aria-invalid": invalid ? "true" : "false",
      "aria-readonly": editable ? "false" : "true",
    }),
    EditorView.editorAttributes.of({
      class: cn("minimal-scrollbar", !editable && "cursor-text"),
    }),
    EditorView.domEventHandlers({
      blur: () => {
        onBlur?.();
        return false;
      },
    }),
  ];

  if (!editable) {
    extensions.push(EditorState.readOnly.of(true));
  }

  if (language === QUERY_EDITOR_LANGUAGE.OPEN_CYPHER) {
    extensions.push(
      openCypherLanguage,
      syntaxHighlighting(editorHighlightStyle),
    );
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(copyValue ?? value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

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
        <div className="flex items-center gap-2">
          {requirementBadge ? (
            <Badge
              variant="tag"
              className="text-text-neutral-secondary border-border-neutral-secondary bg-bg-neutral-primary px-2 py-0 text-[11px]"
            >
              {requirementBadge}
            </Badge>
          ) : null}
          {showCopyButton ? (
            <button
              type="button"
              aria-label={`Copy ${ariaLabel}`}
              onClick={() => void handleCopy()}
              className="text-text-neutral-secondary hover:text-text-neutral-primary shrink-0 cursor-pointer transition-colors"
            >
              {copied ? (
                <Check className="h-3.5 w-3.5" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          ) : null}
        </div>
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
        editable={editable}
        onChange={onChange}
        extensions={extensions}
      />
    </div>
  );
};
