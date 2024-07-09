module.exports = {
  env: {
    node: true,
    es2021: true,
  },
  parser: "@typescript-eslint/parser",
  plugins: ["prettier", "@typescript-eslint", "simple-import-sort"],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/eslint-recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:security/recommended-legacy",
    "prettier",
  ],
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
    ecmaFeatures: {
      jsx: true,
    },
  },
  rules: {
    "no-console": 1,
    eqeqeq: 2,
    // indent: ["error", 2, { SwitchCase: 1 }], // disabled because it clashes with prettier's indent
    quotes: ["error", "double", "avoid-escape"],
    "@typescript-eslint/no-explicit-any": "off",
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
  },
};
