/**
 * AI display-filter help: prompt building, parsing and validation. No `vscode`
 * import, so it is unit-testable; src/ai.ts supplies the language model and
 * the backend's validate_filter.
 *
 * Privacy: the prompt is built only from what `PromptInput` carries: the
 * user's request, the current filter, protocol names (protocol hierarchy)
 * and field names/descriptions (tshark's field list). Packet contents are
 * untrusted and private and never reach the model.
 */

export interface FilterSuggestion {
  filter: string;
  explanation: string;
}

export interface FieldInfo {
  name: string;
  desc?: string;
  type?: string;
}

export interface PromptInput {
  request: string;
  currentFilter: string;
  protocols: readonly string[];
  fields: readonly FieldInfo[];
}

export interface ChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface Rejected {
  filter: string;
  error: string;
}

export const MAX_SUGGESTIONS = 3;
const MAX_REQUEST = 500;
const MAX_PROTOCOLS = 80;
const MAX_FIELDS = 60;
const MAX_FILTER = 500;
const MAX_EXPLANATION = 300;

const STOP_WORDS = new Set(
  (
    "a an and any are as at be by can do for from get give has have how i in is it its me my no not of on or " +
    "only other packet packets please show shows that the their them then there these this those to traffic " +
    "was were what when where which who with without all filter filters display find me want see"
  ).split(" "),
);

/** Words of the request worth a field-name prefix search (lower-case, at most `max`). */
export function extractKeywords(request: string, max = 8): string[] {
  const out: string[] = [];
  for (const raw of request.toLowerCase().split(/[^a-z0-9_.-]+/)) {
    const word = raw.replace(/^[.-]+|[.-]+$/g, "");
    if (word.length < 2 || STOP_WORDS.has(word) || /^[\d.]+$/.test(word) || out.includes(word)) {
      continue;
    }
    out.push(word);
    if (out.length >= max) {
      break;
    }
  }
  return out;
}

const oneLine = (s: string, max: number) => s.replace(/\s+/g, " ").trim().slice(0, max);

/** The prompt for the first request (VS Code's LM API has no system role in 1.90: all goes in one user turn). */
export function buildFilterPrompt(input: PromptInput): string {
  const protocols = [...new Set(input.protocols.map((p) => oneLine(p, 60)).filter(Boolean))].slice(
    0,
    MAX_PROTOCOLS,
  );
  const fields = input.fields.slice(0, MAX_FIELDS).map((f) => {
    const type = f.type ? ` (${oneLine(f.type, 40)})` : "";
    const desc = f.desc ? `: ${oneLine(f.desc, 120)}` : "";
    return `- ${oneLine(f.name, 100)}${type}${desc}`;
  });
  return [
    "You write Wireshark display filters (the language of Wireshark's filter bar and `tshark -Y`).",
    `Suggest up to ${MAX_SUGGESTIONS} display filters for the request below, best first.`,
    "Answer with JSON only (no prose, no code fences), exactly in this shape:",
    '[{"filter": "<display filter>", "explanation": "<one short sentence>"}]',
    "Rules:",
    "- Use only real Wireshark field and protocol names; prefer the candidate fields listed below when they fit.",
    "- Each filter must be one complete, valid display filter on a single line.",
    "- If the request refines the current filter, combine them (for example with &&).",
    "- Keep each explanation under 20 words.",
    "",
    `Request: ${oneLine(input.request, MAX_REQUEST)}`,
    `Current display filter: ${oneLine(input.currentFilter, MAX_FILTER) || "(none)"}`,
    `Protocols in this capture: ${protocols.join(", ") || "(unknown)"}`,
    "Candidate fields:",
    ...(fields.length ? fields : ["(none found)"]),
  ].join("\n");
}

/** Follow-up turn after the first answer produced no valid filter. */
export function buildRetryPrompt(rejected: readonly Rejected[]): string {
  if (!rejected.length) {
    return 'That was not the JSON array requested. Reply with JSON only: [{"filter": "...", "explanation": "..."}]';
  }
  return [
    "tshark rejected these filters:",
    ...rejected.map((r) => `- ${oneLine(r.filter, MAX_FILTER)}: ${oneLine(r.error, 300)}`),
    "Reply with corrected filters, JSON only, in the same shape.",
  ].join("\n");
}

function jsonCandidates(text: string): string[] {
  const cleaned = text.replace(/```[a-zA-Z]*/g, "");
  const out: string[] = [];
  for (const [open, close] of [
    ["[", "]"],
    ["{", "}"],
  ]) {
    const start = cleaned.indexOf(open);
    const end = cleaned.lastIndexOf(close);
    if (start >= 0 && end > start) {
      out.push(cleaned.slice(start, end + 1));
    }
  }
  return out;
}

/**
 * Suggestions from the model's answer: a JSON array of `{filter, explanation}`
 * (also accepted: `{"suggestions": [...]}` or a single object, surrounding prose
 * or code fences). Malformed entries are dropped; duplicates removed; at most `max`.
 */
export function parseSuggestions(text: string, max = MAX_SUGGESTIONS): FilterSuggestion[] {
  let data: unknown;
  for (const candidate of jsonCandidates(text)) {
    try {
      data = JSON.parse(candidate);
      break;
    } catch {
      /* try the next shape */
    }
  }
  if (data && typeof data === "object" && !Array.isArray(data)) {
    const obj = data as { suggestions?: unknown; filter?: unknown };
    data = Array.isArray(obj.suggestions) ? obj.suggestions : [obj];
  }
  if (!Array.isArray(data)) {
    return [];
  }
  const out: FilterSuggestion[] = [];
  for (const item of data) {
    const filter = (item as { filter?: unknown } | null)?.filter;
    const explanation = (item as { explanation?: unknown } | null)?.explanation;
    if (
      typeof filter !== "string" ||
      /[\r\n]/.test(filter.trim()) ||
      !filter.trim() ||
      filter.length > MAX_FILTER
    ) {
      continue;
    }
    const f = filter.trim();
    if (!out.some((s) => s.filter === f)) {
      out.push({
        filter: f,
        explanation: typeof explanation === "string" ? oneLine(explanation, MAX_EXPLANATION) : "",
      });
    }
    if (out.length >= max) {
      break;
    }
  }
  return out;
}

/** Keep the suggestions tshark accepts. `validate` returns an error message, or undefined when valid. */
export async function validateSuggestions(
  suggestions: readonly FilterSuggestion[],
  validate: (filter: string) => Promise<string | undefined>,
): Promise<{ valid: FilterSuggestion[]; rejected: Rejected[] }> {
  const errors = await Promise.all(suggestions.map((s) => validate(s.filter)));
  return {
    valid: suggestions.filter((_s, i) => errors[i] === undefined),
    rejected: suggestions.flatMap((s, i) =>
      errors[i] === undefined ? [] : [{ filter: s.filter, error: errors[i] as string }],
    ),
  };
}

export interface SuggestDeps {
  /** Send the conversation to the language model; resolves to its full text answer. */
  ask: (turns: ChatTurn[]) => Promise<string>;
  validate: (filter: string) => Promise<string | undefined>;
}

/** Ask, parse, validate; if nothing valid came back, ask once more with tshark's errors. */
export async function suggestFilters(
  deps: SuggestDeps,
  input: PromptInput,
  options: { retry?: boolean } = {},
): Promise<{ suggestions: FilterSuggestion[]; rejected: Rejected[] }> {
  const turns: ChatTurn[] = [{ role: "user", content: buildFilterPrompt(input) }];
  const answer = await deps.ask(turns);
  const first = await validateSuggestions(parseSuggestions(answer), deps.validate);
  if (first.valid.length || options.retry === false) {
    return { suggestions: first.valid, rejected: first.rejected };
  }
  turns.push(
    { role: "assistant", content: answer },
    { role: "user", content: buildRetryPrompt(first.rejected) },
  );
  const second = await validateSuggestions(parseSuggestions(await deps.ask(turns)), deps.validate);
  return { suggestions: second.valid, rejected: [...first.rejected, ...second.rejected] };
}
