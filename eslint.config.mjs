// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["out/**", "node_modules/**", ".vscode-test/**", ".venv/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["src/**/*.ts", "test/extension/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      eqeqeq: ["error", "always"],
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Never use innerHTML: packet data is untrusted." },
      ],
    },
  },
  {
    // Webview scripts run in the browser sandbox (and lib.js also under Node tests).
    files: ["src/webview/**/*.js", "test/webview/**/*.js"],
    languageOptions: {
      sourceType: "script",
      globals: {
        window: "readonly",
        document: "readonly",
        acquireVsCodeApi: "readonly",
        requestAnimationFrame: "readonly",
        cancelAnimationFrame: "readonly",
        getComputedStyle: "readonly",
        ResizeObserver: "readonly",
        HTMLElement: "readonly",
        KeyboardEvent: "readonly",
        MouseEvent: "readonly",
        module: "writable",
        require: "readonly",
        globalThis: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        console: "readonly",
      },
    },
    rules: {
      "@typescript-eslint/no-require-imports": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      eqeqeq: ["error", "always"],
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Never use innerHTML: packet data is untrusted." },
        { property: "outerHTML", message: "Never use outerHTML: packet data is untrusted." },
      ],
      "no-restricted-syntax": [
        "error",
        { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: "No HTML injection." },
      ],
    },
  },
  {
    // Node-side webview tests (mocha tdd).
    files: ["test/webview/**/*.js"],
    languageOptions: {
      globals: {
        suite: "readonly",
        test: "readonly",
        suiteSetup: "readonly",
        suiteTeardown: "readonly",
        setup: "readonly",
        teardown: "readonly",
        process: "readonly",
        __dirname: "readonly",
        URL: "readonly",
      },
    },
  },
);
