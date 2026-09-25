// Type-checking support for the plain-JS webview (see tsconfig.webview.json).
declare function acquireVsCodeApi(): {
  postMessage(message: unknown): void;
  getState(): any; // eslint-disable-line @typescript-eslint/no-explicit-any
  setState(state: unknown): void;
};
