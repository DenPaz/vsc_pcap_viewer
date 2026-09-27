/**
 * The setup check behind the Get Started walkthrough and _PCAP: Check Python
 * and TShark_: is there a Python the backend can run on, and does the backend
 * find tshark? No `vscode` import, so it is unit-tested with fakes.
 */
import { MIN_PYTHON } from "./backendClient";

export type PythonStatus =
  { ok: true; version: string; command: string } | { ok: false; error: string };

export type TsharkStatus =
  { ok: true; version: string; path: string } | { ok: false; error: string; skipped?: true };

export interface EnvironmentStatus {
  python: PythonStatus;
  tshark: TsharkStatus;
}

export interface EnvironmentDeps {
  findPython(
    configured: string | undefined,
  ): { python: string[]; version: string } | { error: string };
  /** Start the backend with `python` and run `initialize` (which locates tshark). */
  initialize(
    python: string[],
    tsharkPath: string | undefined,
  ): Promise<{ version: string; tsharkPath: string }>;
}

/** Check Python first: without it the backend can't look for tshark. */
export async function checkEnvironment(
  settings: { pythonPath: string; tsharkPath: string },
  deps: EnvironmentDeps,
): Promise<EnvironmentStatus> {
  const py = deps.findPython(settings.pythonPath || undefined);
  if ("error" in py) {
    return {
      python: { ok: false, error: py.error },
      tshark: {
        ok: false,
        skipped: true,
        error: `TShark is checked once Python ${MIN_PYTHON.join(".")} is found.`,
      },
    };
  }
  const python: PythonStatus = { ok: true, version: py.version, command: py.python.join(" ") };
  try {
    const init = await deps.initialize(py.python, settings.tsharkPath || undefined);
    return {
      python,
      tshark: { ok: true, version: tsharkVersion(init.version), path: init.tsharkPath },
    };
  } catch (err) {
    return {
      python,
      tshark: { ok: false, error: err instanceof Error ? err.message : String(err) },
    };
  }
}

/** "TShark (Wireshark) 4.6.1 (Git v4.6.1 packaged as …)" → "4.6.1". */
export function tsharkVersion(banner: string): string {
  return /(\d+\.\d+\.\d+)/.exec(banner)?.[1] ?? banner.trim();
}

/** One line for a notification. */
export function environmentSummary(status: EnvironmentStatus): string {
  const { python, tshark } = status;
  if (python.ok && tshark.ok) {
    return `Ready: Python ${python.version} (${python.command}) and TShark ${tshark.version} (${tshark.path}).`;
  }
  if (!python.ok) {
    return python.error;
  }
  return `Python ${python.version} is fine, but TShark isn't: ${(tshark as { error: string }).error}`;
}

/** Which setting fixes the first problem. */
export function settingToFix(status: EnvironmentStatus): "pythonPath" | "tsharkPath" | undefined {
  return !status.python.ok ? "pythonPath" : !status.tshark.ok ? "tsharkPath" : undefined;
}
