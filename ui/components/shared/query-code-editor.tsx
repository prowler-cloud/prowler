"use client";

import {
  HighlightStyle,
  StreamLanguage,
  type StringStream,
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

export const QUERY_EDITOR_LANGUAGE = {
  OPEN_CYPHER: "openCypher",
  PLAIN_TEXT: "plainText",
  JSON: "json",
  SHELL: "shell",
  HCL: "hcl",
  BICEP: "bicep",
  YAML: "yaml",
} as const;

export type QueryEditorLanguage =
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

const SHELL_KEYWORDS = new Set([
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "for",
  "in",
  "do",
  "done",
  "while",
  "until",
  "case",
  "esac",
  "function",
  "return",
  "export",
  "local",
  "readonly",
  "declare",
  "typeset",
  "unset",
  "shift",
  "break",
  "continue",
  "select",
  "time",
  "trap",
]);

const SHELL_COMMANDS = new Set([
  "aws",
  "az",
  "gcloud",
  "kubectl",
  "terraform",
  "echo",
  "grep",
  "sed",
  "awk",
  "curl",
  "wget",
  "chmod",
  "chown",
  "mkdir",
  "rm",
  "cp",
  "mv",
  "cat",
  "ls",
]);

const HCL_KEYWORDS = new Set([
  "resource",
  "data",
  "variable",
  "output",
  "locals",
  "module",
  "provider",
  "terraform",
  "backend",
  "required_providers",
  "dynamic",
  "for_each",
  "count",
  "depends_on",
  "lifecycle",
  "provisioner",
  "connection",
]);

const HCL_FUNCTIONS = new Set([
  "lookup",
  "merge",
  "join",
  "split",
  "length",
  "element",
  "concat",
  "format",
  "replace",
  "regex",
  "tolist",
  "tomap",
  "toset",
  "try",
  "can",
  "file",
  "templatefile",
  "jsonencode",
  "jsondecode",
  "yamlencode",
  "yamldecode",
  "base64encode",
  "base64decode",
  "md5",
  "sha256",
  "cidrsubnet",
  "cidrhost",
]);

interface JsonParserState {
  inString: boolean;
  stringIsProperty: boolean;
  escapeNext: boolean;
}

const jsonLanguage = StreamLanguage.define<JsonParserState>({
  startState() {
    return {
      inString: false,
      stringIsProperty: false,
      escapeNext: false,
    };
  },
  token(stream, state) {
    if (state.inString) {
      while (!stream.eol()) {
        const next = stream.next();

        if (state.escapeNext) {
          state.escapeNext = false;
          continue;
        }

        if (next === "\\") {
          state.escapeNext = true;
          continue;
        }

        if (next === '"') {
          state.inString = false;
          return state.stringIsProperty ? "propertyName" : "string";
        }
      }

      return state.stringIsProperty ? "propertyName" : "string";
    }

    if (stream.eatSpace()) {
      return null;
    }

    if (stream.peek() === '"') {
      const restOfLine = stream.string.slice(stream.pos);
      state.inString = true;
      state.escapeNext = false;
      state.stringIsProperty = /^\s*"([^"\\]|\\.)*"\s*:/.test(restOfLine);
      stream.next();
      return state.stringIsProperty ? "propertyName" : "string";
    }

    if (stream.match(/[{}\[\],:]/)) {
      return "punctuation";
    }

    if (stream.match(/-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/)) {
      return "number";
    }

    if (stream.match(/\b(?:true|false|null)\b/)) {
      return "keyword";
    }

    stream.next();
    return null;
  },
});

const BICEP_KEYWORDS = new Set([
  "resource",
  "module",
  "param",
  "var",
  "output",
  "type",
  "metadata",
  "import",
  "using",
  "extension",
  "targetScope",
  "existing",
  "if",
  "for",
  "in",
  "true",
  "false",
  "null",
]);

const BICEP_DECORATORS = new Set([
  "description",
  "secure",
  "minLength",
  "maxLength",
  "minValue",
  "maxValue",
  "allowed",
  "metadata",
  "batchSize",
  "sys",
]);

const BICEP_FUNCTIONS = new Set([
  "concat",
  "format",
  "toLower",
  "toUpper",
  "substring",
  "replace",
  "split",
  "join",
  "length",
  "contains",
  "empty",
  "first",
  "last",
  "indexOf",
  "array",
  "union",
  "intersection",
  "resourceId",
  "subscriptionResourceId",
  "tenantResourceId",
  "reference",
  "listKeys",
  "listAccountSas",
  "uniqueString",
  "guid",
  "base64",
  "uri",
  "environment",
  "subscription",
  "resourceGroup",
  "tenant",
]);

interface OpenCypherParserState {
  inBlockComment: boolean;
  inString: "'" | '"' | null;
}

interface ShellParserState {
  inString: "'" | '"' | null;
}

interface HclParserState {
  inBlockComment: boolean;
  inString: '"' | null;
  expectBlockType: boolean;
  heredocTerminator: string | null;
}

interface BicepParserState {
  inBlockComment: boolean;
  inString: "'" | null;
  expectResourceType: boolean;
}

interface YamlParserState {
  inString: "'" | '"' | null;
  inBlockScalar: boolean;
  blockScalarIndent: number;
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

const shellLanguage = StreamLanguage.define<ShellParserState>({
  startState() {
    return {
      inString: null,
    };
  },
  token(stream, state) {
    if (state.inString) {
      let escaped = false;

      while (!stream.eol()) {
        const next = stream.next();

        if (escaped) {
          escaped = false;
          continue;
        }

        if (next === "\\" && state.inString === '"') {
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

    if (stream.peek() === "#") {
      stream.skipToEnd();
      return "comment";
    }

    if (stream.match(/\$\([^)]+\)/)) {
      return "variableName";
    }

    if (stream.match(/\$\{[A-Za-z_][\w]*\}/)) {
      return "variableName";
    }

    if (stream.match(/\$[A-Za-z_][\w]*/)) {
      return "variableName";
    }

    const quote = stream.peek();
    if (quote === "'" || quote === '"') {
      state.inString = quote;
      stream.next();
      return "string";
    }

    if (stream.match(/--[A-Za-z0-9][\w-]*/)) {
      return "operator";
    }

    if (stream.match(/-[A-Za-z0-9]+/)) {
      return "operator";
    }

    if (stream.match(/\|\||&&|>>|[|><;]/)) {
      return "operator";
    }

    if (stream.match(/\d+(?:\.\d+)?/)) {
      return "number";
    }

    if (stream.match(/[A-Za-z_][\w-]*/)) {
      const currentValue = stream.current();
      const normalizedValue = currentValue.toLowerCase();

      if (SHELL_KEYWORDS.has(normalizedValue)) {
        return "keyword";
      }

      if (SHELL_COMMANDS.has(normalizedValue)) {
        return "function";
      }

      return "variableName";
    }

    stream.next();
    return null;
  },
});

const hclLanguage = StreamLanguage.define<HclParserState>({
  startState() {
    return {
      inBlockComment: false,
      inString: null,
      expectBlockType: false,
      heredocTerminator: null,
    };
  },
  token(stream, state) {
    if (state.heredocTerminator) {
      // Match the closing terminator on its own line, including indented <<-EOF forms.
      if (
        stream.sol() &&
        stream.match(new RegExp(`^\\s*${state.heredocTerminator}\\s*$`))
      ) {
        state.heredocTerminator = null;
        return "keyword";
      }

      stream.skipToEnd();
      return "string";
    }

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

    if (stream.match("#") || stream.match("//")) {
      stream.skipToEnd();
      return "comment";
    }

    if (stream.match("/*")) {
      state.inBlockComment = true;
      return "comment";
    }

    if (stream.match(/\$\{[^}]+\}/)) {
      return "variableName";
    }

    if (stream.peek() === '"') {
      if (state.expectBlockType) {
        state.expectBlockType = false;
        stream.next(); // opening "
        while (!stream.eol()) {
          const ch = stream.next();
          if (ch === "\\") {
            stream.next(); // skip escaped char
          } else if (ch === '"') {
            break;
          }
        }
        return "typeName";
      }

      state.inString = '"';
      stream.next();
      return "string";
    }

    if (stream.match(/[{}\[\]()]/)) {
      return "punctuation";
    }

    // Heredoc (<<EOF, <<-EOF) — must be before generic operator matcher
    if (stream.match(/<<-?([A-Za-z_][\w]*)/)) {
      state.heredocTerminator = stream.current().replace(/^<<-?/, "");
      return "keyword";
    }

    if (stream.match(/=>|\.\.\.|==|!=|>=|<=|[=><?:]/)) {
      return "operator";
    }

    if (stream.match(/\b(?:true|false)\b/)) {
      return "keyword";
    }

    if (stream.match(/\d+(?:\.\d+)?/)) {
      return "number";
    }

    if (stream.match(/[A-Za-z_][\w-]*/)) {
      const currentValue = stream.current();
      const normalizedValue = currentValue.toLowerCase();

      if (HCL_KEYWORDS.has(normalizedValue)) {
        state.expectBlockType =
          normalizedValue === "resource" || normalizedValue === "data";
        return "keyword";
      }

      if (
        HCL_FUNCTIONS.has(normalizedValue) &&
        stream.match(/\s*(?=\()/, false)
      ) {
        return "function";
      }

      if (state.expectBlockType) {
        state.expectBlockType = false;
        return "typeName";
      }

      if (stream.match(/\s*(?==)/, false)) {
        return "propertyName";
      }

      return "variableName";
    }

    stream.next();
    return null;
  },
});

const yamlLanguage = StreamLanguage.define<YamlParserState>({
  startState() {
    return {
      inString: null,
      inBlockScalar: false,
      blockScalarIndent: 0,
    };
  },
  token(stream, state) {
    // Block scalar continuation (| or > multiline strings)
    if (state.inBlockScalar) {
      // Blank lines are always part of a block scalar.
      if (stream.match(/^\s*$/)) {
        stream.skipToEnd();
        return "string";
      }

      const indent = stream.indentation();

      if (indent > state.blockScalarIndent) {
        stream.skipToEnd();
        return "string";
      }

      state.inBlockScalar = false;
      state.blockScalarIndent = 0;
    }

    // Continue quoted strings across tokens
    if (state.inString) {
      let escaped = false;

      while (!stream.eol()) {
        const next = stream.next();

        if (escaped) {
          escaped = false;
          continue;
        }

        if (next === "\\" && state.inString === '"') {
          escaped = true;
          continue;
        }

        if (next === state.inString) {
          state.inString = null;
          break;
        }
      }

      return "string";
    }

    if (stream.eatSpace()) {
      return null;
    }

    // Comments
    if (stream.peek() === "#") {
      stream.skipToEnd();
      return "comment";
    }

    // Document markers
    if (stream.sol() && (stream.match("---") || stream.match("..."))) {
      return "keyword";
    }

    // Anchors & aliases
    if (stream.match(/[&*][A-Za-z_][\w]*/)) {
      return "variableName";
    }

    // CloudFormation intrinsic tags (!Ref, !Sub, !GetAtt, etc.)
    if (stream.match(/![A-Za-z][A-Za-z0-9]*/)) {
      return "typeName";
    }

    // Tags (!!str, !!map, etc.)
    if (stream.match(/!![A-Za-z]+/)) {
      return "typeName";
    }

    // Quoted strings
    const quote = stream.peek();
    if (quote === "'" || quote === '"') {
      state.inString = quote;
      stream.next();
      return "string";
    }

    // Block scalar indicators (| or >)
    if (
      stream.sol() === false &&
      (stream.peek() === "|" || stream.peek() === ">")
    ) {
      const prevChar = stream.string.charAt(stream.pos - 1);

      if (prevChar === " " || prevChar === ":") {
        stream.next();
        // Eat optional modifiers like |-, |+, |2
        stream.match(/[-+]?\d?/);
        state.inBlockScalar = true;
        state.blockScalarIndent = stream.indentation();
        return "operator";
      }
    }

    // List item marker
    if (stream.match(/^-(?=\s)/)) {
      return "punctuation";
    }

    // Key: value pattern — supports CloudFormation long-form intrinsics (Fn::Sub:)
    if (stream.match(/[A-Za-z_][\w./-]*(?:::[A-Za-z_][\w]*)*(?=\s*:(?!:))/)) {
      return "propertyName";
    }

    // Booleans & null (YAML spec values)
    if (stream.match(/\b(?:true|false|yes|no|on|off|null)\b/i)) {
      return "keyword";
    }

    // Numbers (integers, floats, hex, octal)
    if (
      stream.match(
        /^[-+]?(?:0x[0-9a-fA-F]+|0o[0-7]+|0b[01]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)/,
      )
    ) {
      return "number";
    }

    // Colon separator
    if (stream.match(":")) {
      return "punctuation";
    }

    // Braces/brackets (flow style)
    if (stream.match(/[{}\[\],]/)) {
      return "punctuation";
    }

    // Tilde (null alias)
    if (stream.match("~")) {
      return "keyword";
    }

    // Unquoted strings / values — consume word
    if (stream.match(/[^\s#:,\[\]{}]+/)) {
      return "string";
    }

    stream.next();
    return null;
  },
});

function readBicepStringSegment(
  stream: StringStream,
  includeOpeningQuote = false,
) {
  if (includeOpeningQuote) {
    stream.next();
  }

  while (!stream.eol()) {
    if (stream.match("${")) {
      stream.backUp(2);
      break;
    }

    const next = stream.next();

    if (next === "'" && stream.peek() === "'") {
      stream.next();
      continue;
    }

    if (next === "'") {
      stream.backUp(1);
      break;
    }
  }
}

const bicepLanguage = StreamLanguage.define<BicepParserState>({
  startState() {
    return {
      inBlockComment: false,
      inString: null,
      expectResourceType: false,
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
      if (stream.match("${")) {
        let depth = 1;

        while (!stream.eol() && depth > 0) {
          const next = stream.next();

          if (next === "{") {
            depth += 1;
            continue;
          }

          if (next === "}") {
            depth -= 1;
          }
        }

        return "variableName";
      }

      readBicepStringSegment(stream);

      if (stream.peek() !== "'") {
        return "string";
      }

      if (stream.peek() === "'") {
        state.inString = null;
        stream.next();
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

    if (stream.match(/@[A-Za-z_][\w]*/)) {
      const decorator = stream.current().slice(1);

      if (BICEP_DECORATORS.has(decorator)) {
        return "keyword";
      }

      return "keyword";
    }

    if (stream.peek() === "'") {
      if (state.expectResourceType) {
        state.expectResourceType = false;
        // Consume the full quoted resource type including both quotes
        stream.next(); // opening '
        while (!stream.eol()) {
          const ch = stream.next();
          if (ch === "'" && stream.peek() === "'") {
            stream.next(); // escaped ''
            continue;
          }
          if (ch === "'") {
            break; // closing '
          }
        }
        return "typeName";
      }

      stream.next(); // consume opening '
      state.inString = "'";
      return "string";
    }

    if (stream.match(/[A-Za-z_][\w-]*(?=\s*:)/)) {
      return "propertyName";
    }

    if (stream.match(/\?\?|==|!=|>=|<=|=|>|<|\?|:|!/)) {
      return "operator";
    }

    if (stream.match(/[{}\[\]()]/)) {
      return "punctuation";
    }

    if (stream.match(/-?\d+(?:\.\d+)?/)) {
      return "number";
    }

    if (stream.match(/[A-Za-z_][\w]*/)) {
      const currentValue = stream.current();

      if (BICEP_KEYWORDS.has(currentValue)) {
        state.expectResourceType =
          currentValue === "resource" || currentValue === "module";
        return "keyword";
      }

      if (
        BICEP_FUNCTIONS.has(currentValue) &&
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
  visibleLabel?: string | null;
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
  visibleLabel = ariaLabel,
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
  } else if (language === QUERY_EDITOR_LANGUAGE.SHELL) {
    extensions.push(shellLanguage, syntaxHighlighting(editorHighlightStyle));
  } else if (language === QUERY_EDITOR_LANGUAGE.HCL) {
    extensions.push(hclLanguage, syntaxHighlighting(editorHighlightStyle));
  } else if (language === QUERY_EDITOR_LANGUAGE.JSON) {
    extensions.push(jsonLanguage, syntaxHighlighting(editorHighlightStyle));
  } else if (language === QUERY_EDITOR_LANGUAGE.BICEP) {
    extensions.push(bicepLanguage, syntaxHighlighting(editorHighlightStyle));
  } else if (language === QUERY_EDITOR_LANGUAGE.YAML) {
    extensions.push(yamlLanguage, syntaxHighlighting(editorHighlightStyle));
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
        {visibleLabel ? (
          <span className="text-text-neutral-secondary text-xs font-medium">
            {visibleLabel}
          </span>
        ) : (
          <span aria-hidden="true" />
        )}
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
