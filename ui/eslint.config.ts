import nextPlugin from "@next/eslint-plugin-next";
import prettierConfig from "eslint-config-prettier/flat";
import { createTypeScriptImportResolver } from "eslint-import-resolver-typescript";
import importX, { createNodeResolver } from "eslint-plugin-import-x";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactPlugin from "eslint-plugin-react";
import reactHooksPlugin from "eslint-plugin-react-hooks";
import security from "eslint-plugin-security";
import globals from "globals";
import tseslint from "typescript-eslint";

// Existing violations of these rules are frozen in eslint-suppressions.json.
const PALETTE_COLOR_CLASS =
  "/\\b(bg|text|border(-[trblxy])?|ring|ring-offset|outline|fill|stroke|from|via|to|divide|placeholder|decoration|shadow|accent|caret)-(red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose|slate|gray|zinc|neutral|stone)-(50|[1-9]00|950)\\b/";
const HEX_ARBITRARY_CLASS = "/-\\[#[0-9a-fA-F]{3,8}\\]/";
const PALETTE_MESSAGE =
  "Raw Tailwind palette colors bypass the design tokens. Use a token from styles/globals.css or a component variant.";
const HEX_MESSAGE =
  "Hex colors bypass the design tokens. Use a token from styles/globals.css.";

export default tseslint.config(
  {
    ignores: [
      ".now/**",
      "**/*.css",
      ".changeset/**",
      "dist/**",
      "esm/**",
      "public/**",
      "tests/**",
      "scripts/**",
      "*.config.js",
      "*.config.mjs",
      "auth.config.ts",
      "eslint.config.ts",
      "knip.config.ts",
      "playwright.config.ts",
      "vitest.config.ts",
      ".DS_Store",
      "node_modules/**",
      "coverage/**",
      ".next/**",
      "build/**",
      "next-env.d.ts",
    ],
  },
  importX.flatConfigs.recommended,
  importX.flatConfigs.typescript,
  {
    files: ["**/*.{ts,tsx,js,jsx}"],
    linterOptions: {
      reportUnusedDisableDirectives: "error",
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
      "@next/next": nextPlugin,
      react: reactPlugin,
      "react-hooks": reactHooksPlugin,
      "jsx-a11y": jsxA11y,
      security,
    },
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: {
          allowDefaultProject: [
            // Duplicate of events-timeline.test.ts in the same folder;
            // TypeScript only picks the .ts sibling, so this .tsx file is
            // outside the project graph. Tracked for follow-up cleanup.
            "components/shared/events-timeline/events-timeline.test.tsx",
          ],
        },
        tsconfigRootDir: import.meta.dirname,
        ecmaVersion: "latest",
        sourceType: "module",
        ecmaFeatures: {
          jsx: true,
        },
      },
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.es2021,
        React: "readonly",
      },
    },
    settings: {
      react: {
        version: "detect",
      },
      "import-x/resolver-next": [
        createTypeScriptImportResolver({
          alwaysTryTypes: true,
          project: "./tsconfig.json",
        }),
        createNodeResolver(),
      ],
    },
    rules: {
      "no-console": ["error", { allow: ["error"] }],
      eqeqeq: "error",
      quotes: ["error", "double", { avoidEscape: true }],

      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          enableAutofixRemoval: { imports: true },
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],

      "security/detect-object-injection": "off",

      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "react",
              importNames: ["default", "memo", "useMemo", "useCallback"],
              message:
                "Use named imports from react. The React Compiler replaces memo, useMemo and useCallback.",
            },
          ],
          patterns: [
            // Icons must ship in the bundle: air-gapped deployments cannot
            // reach runtime icon APIs.
            {
              group: ["@iconify/*"],
              message:
                "Iconify loads icons over the network. Use lucide-react or components/icons.",
            },
            {
              group: ["@/components/ui", "@/components/ui/*"],
              message:
                "components/ui only re-exports shadcn for the Prowler Cloud overlay. Import from @/components/shadcn.",
            },
          ],
        },
      ],
      "no-restricted-syntax": [
        "error",
        {
          selector: `Literal[value=${PALETTE_COLOR_CLASS}]`,
          message: PALETTE_MESSAGE,
        },
        {
          selector: `TemplateElement[value.raw=${PALETTE_COLOR_CLASS}]`,
          message: PALETTE_MESSAGE,
        },
        {
          selector: `Literal[value=${HEX_ARBITRARY_CLASS}]`,
          message: HEX_MESSAGE,
        },
        {
          selector: `TemplateElement[value.raw=${HEX_ARBITRARY_CLASS}]`,
          message: HEX_MESSAGE,
        },
        {
          selector:
            "JSXAttribute[name.name='className'] Literal[value=/var\\(--/]",
          message:
            "Do not use var() in className. Use the token's Tailwind class, or the style prop for library props.",
        },
        {
          selector:
            "JSXAttribute[name.name='className'] TemplateElement[value.raw=/var\\(--/]",
          message:
            "Do not use var() in className. Use the token's Tailwind class, or the style prop for library props.",
        },
        {
          selector:
            "TSTypeAliasDeclaration > TSUnionType.typeAnnotation:not(:has(> :not(TSLiteralType:has(> Literal.literal[value=/^/]))))",
          message:
            "Declare a const object and derive the type: (typeof X)[keyof typeof X].",
        },
      ],

      "eol-last": ["error", "always"],

      "import-x/order": [
        "error",
        {
          groups: [
            "builtin",
            "external",
            "internal",
            "parent",
            "sibling",
            "index",
          ],
          "newlines-between": "always",
          alphabetize: { order: "asc", caseInsensitive: true },
        },
      ],
      // Pre-existing duplicate exports and re-export shape mismatches are
      // tracked separately; the migration keeps behavior parity with the
      // legacy config until the rule is enforced in the canonical Base layer.
      "import-x/export": "off",

      "jsx-a11y/anchor-is-valid": [
        "error",
        {
          components: ["Link"],
          specialLink: ["hrefLeft", "hrefRight"],
          aspects: ["invalidHref", "preferButton"],
        },
      ],
      "jsx-a11y/alt-text": "error",

      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      // React Compiler rules from the plugin's recommended set, as errors so
      // bulk suppressions can freeze the existing violations.
      "react-hooks/component-hook-factories": "error",
      "react-hooks/config": "error",
      "react-hooks/error-boundaries": "error",
      "react-hooks/gating": "error",
      "react-hooks/globals": "error",
      "react-hooks/immutability": "error",
      "react-hooks/incompatible-library": "error",
      "react-hooks/preserve-manual-memoization": "error",
      "react-hooks/purity": "error",
      "react-hooks/refs": "error",
      "react-hooks/set-state-in-effect": "error",
      "react-hooks/set-state-in-render": "error",
      "react-hooks/static-components": "error",
      "react-hooks/unsupported-syntax": "error",
      "react-hooks/use-memo": "error",
      "react-hooks/void-use-memo": "error",

      "@next/next/no-html-link-for-pages": "error",
      "@next/next/no-img-element": "warn",
      "@next/next/no-sync-scripts": "error",
    },
  },
  prettierConfig,
);
