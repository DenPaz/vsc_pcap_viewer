/**
 * The parts of VS Code's language model tools API that PCAP Viewer uses
 * (`vscode.lm.registerTool`, tool call/result parts, `sendRequest` with
 * `tools`, `response.stream`). They arrived after 1.90, our `engines.vscode`,
 * and `@types/vscode` is pinned to it (.ncurc.cjs), so they are declared here
 * and detected at runtime, the way `vscode.chat.createChatParticipant` is.
 * Without them, `@pcap` keeps its behaviour without tools.
 */
import * as vscode from "vscode";
import type { LoopMessage, LoopModel, LoopPart, ToolSpec } from "./aiTools";

export interface ToolInvocationOptions {
  input: unknown;
  toolInvocationToken?: unknown;
}

export interface LanguageModelToolImpl {
  invoke(options: ToolInvocationOptions, token: vscode.CancellationToken): Promise<unknown>;
}

interface TextPart {
  value: string;
}

interface ToolCallPart {
  callId: string;
  name: string;
  input: unknown;
}

interface ToolsApi {
  registerTool(name: string, tool: LanguageModelToolImpl): vscode.Disposable;
  tools?: readonly { name: string }[];
}

type Ctor<A extends unknown[], T> = new (...args: A) => T;

export interface ToolsRuntime {
  registerTool(name: string, tool: LanguageModelToolImpl): vscode.Disposable;
  /** The tools VS Code knows (every extension's). */
  toolNames(): string[];
  /** A tool's result as VS Code wants it back from `invoke`. */
  result(text: string): unknown;
  /** VS Code's chat model as a LoopModel (tool calls in, results out). */
  loopModel(
    model: vscode.LanguageModelChat,
    justification: string,
    token: vscode.CancellationToken,
  ): LoopModel;
}

/** VS Code's tools API, or undefined when this VS Code doesn't have it. */
export function toolsRuntime(): ToolsRuntime | undefined {
  const api = vscode.lm as unknown as Partial<ToolsApi> | undefined;
  const v = vscode as unknown as Record<string, unknown>;
  const TextPartC = v.LanguageModelTextPart as Ctor<[string], TextPart> | undefined;
  const CallPartC = v.LanguageModelToolCallPart as
    Ctor<[string, string, object], ToolCallPart> | undefined;
  const ResultPartC = v.LanguageModelToolResultPart as
    Ctor<[string, unknown[]], unknown> | undefined;
  const ResultC = v.LanguageModelToolResult as Ctor<[unknown[]], unknown> | undefined;
  if (
    typeof api?.registerTool !== "function" ||
    !TextPartC ||
    !CallPartC ||
    !ResultPartC ||
    !ResultC
  ) {
    return undefined;
  }
  const registerTool = api.registerTool.bind(api);
  // User()/Assistant() take an array of parts where tools exist (1.90's types say string).
  const message = (role: "user" | "assistant", parts: unknown[]) =>
    (role === "user"
      ? (vscode.LanguageModelChatMessage.User as (c: unknown) => vscode.LanguageModelChatMessage)
      : (vscode.LanguageModelChatMessage.Assistant as (
          c: unknown,
        ) => vscode.LanguageModelChatMessage))(parts);
  const toVscode = (m: LoopMessage) =>
    message(
      m.role,
      m.parts.map((p) =>
        p.type === "text"
          ? new TextPartC(p.text)
          : p.type === "call"
            ? new CallPartC(p.callId, p.name, (p.input ?? {}) as object)
            : new ResultPartC(p.callId, [new TextPartC(p.text)]),
      ),
    );
  return {
    registerTool,
    toolNames: () => (api.tools ?? []).map((t) => t.name),
    result: (text) => new ResultC([new TextPartC(text)]),
    loopModel: (model, justification, token) => ({
      async *send(messages: readonly LoopMessage[], tools: readonly ToolSpec[]) {
        const options = {
          justification,
          tools: tools.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        } as vscode.LanguageModelChatRequestOptions;
        const response = await model.sendRequest(messages.map(toVscode), options, token);
        const stream = (response as unknown as { stream?: AsyncIterable<unknown> }).stream;
        if (!stream) {
          for await (const text of response.text) {
            yield { type: "text", text } satisfies LoopPart;
          }
          return;
        }
        for await (const part of stream) {
          if (part instanceof CallPartC) {
            yield { type: "call", callId: part.callId, name: part.name, input: part.input };
          } else if (part instanceof TextPartC) {
            yield { type: "text", text: part.value };
          }
        }
      },
    }),
  };
}
