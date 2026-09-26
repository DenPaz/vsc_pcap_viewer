// Settings for `ncu -u` (npm-check-updates, e.g. `pnpm dlx npm-check-updates -u`).
module.exports = {
  // Respect peer ranges: typescript-eslint caps the TypeScript version.
  peer: true,
  // Must not exceed engines.vscode (vsce refuses to package); raise both together.
  reject: ["@types/vscode"],
  // Match the Node that VS Code 1.90 runs extensions on (Node 20).
  target: (name) => (name === "@types/node" ? "minor" : "latest"),
};
