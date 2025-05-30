module.exports = {
  env: {
    node: true,
    es2021: true,
  },
  parser: "@typescript-eslint/parser",
  plugins: ["prettier", "@typescript-eslint", "simple-import-sort", "jsx-a11y"],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:security/recommended-legacy",
    "plugin:jsx-a11y/recommended",
    "eslint-config-prettier",
    "prettier",
    "next/core-web-vitals",
  ],
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
    ecmaFeatures: {
      jsx: true,
    },
  },
  rules: {
    // console.error are allowed but no console.log
    "no-console": ["error", { allow: ["error"] }],
    eqeqeq: 2,
    quotes: ["error", "double", "avoid-escape"],
    "@typescript-eslint/no-explicit-any": "off",
    "security/detect-object-injection": "off",
    "prettier/prettier": [
      "error",
      {
        endOfLine: "auto",
        tabWidth: 2,
        useTabs: false,
      },
    ],
    "eol-last": ["error", "always"],
    "simple-import-sort/imports": "error",
    "simple-import-sort/exports": "error",
    "jsx-a11y/anchor-is-valid": [
      "error",
      {
        components: ["Link"],
        specialLink: ["hrefLeft", "hrefRight"],
        aspects: ["invalidHref", "preferButton"],
      },
    ],
    "jsx-a11y/alt-text": "error",
    "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
  },
};
