import { dirname } from "path";
import { fileURLToPath } from "url";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import prettierPlugin from "eslint-plugin-prettier";
import simpleImportSort from "eslint-plugin-simple-import-sort";
import jsxA11y from "eslint-plugin-jsx-a11y";
import security from "eslint-plugin-security";
import unusedImports from "eslint-plugin-unused-imports";
import nextPlugin from "@next/eslint-plugin-next";
import reactPlugin from "eslint-plugin-react";
import reactHooksPlugin from "eslint-plugin-react-hooks";
import globals from "globals";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default [
  // Global ignores (replaces .eslintignore)
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
      ".DS_Store",
      "node_modules/**",
      "coverage/**",
      ".next/**",
      "build/**",
      "next-env.d.ts",
    ],
  },

  // TypeScript and React files configuration
  {
    files: ["**/*.{ts,tsx,js,jsx}"],
    plugins: {
      "@typescript-eslint": tsPlugin,
      "@next/next": nextPlugin,
      react: reactPlugin,
      "react-hooks": reactHooksPlugin,
      prettier: prettierPlugin,
      "simple-import-sort": simpleImportSort,
      "jsx-a11y": jsxA11y,
      security: security,
      "unused-imports": unusedImports,
    },
    languageOptions: {
      parser: tsParser,
      parserOptions: {
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
    },
    rules: {
      // Console rules - allow console.error but no console.log
      "no-console": ["error", { allow: ["error"] }],
      eqeqeq: 2,
      quotes: ["error", "double", "avoid-escape"],

      // TypeScript rules
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],

      // Security
      "security/detect-object-injection": "off",

      // Prettier integration
      "prettier/prettier": [
        "error",
        {
          endOfLine: "auto",
          tabWidth: 2,
          useTabs: false,
        },
      ],
      "eol-last": ["error", "always"],

      // Import sorting
      "simple-import-sort/imports": "error",
      "simple-import-sort/exports": "error",

      // Unused imports
      "unused-imports/no-unused-imports": "error",

      // Accessibility
      "jsx-a11y/anchor-is-valid": [
        "error",
        {
          components: ["Link"],
          specialLink: ["hrefLeft", "hrefRight"],
          aspects: ["invalidHref", "preferButton"],
        },
      ],
      "jsx-a11y/alt-text": "error",

      // React Hooks
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",

      // Next.js specific rules
      "@next/next/no-html-link-for-pages": "error",
      "@next/next/no-img-element": "warn",
      "@next/next/no-sync-scripts": "error",
    },
  },
];
