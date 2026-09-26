/**
 * Lua dissector scaffolding for "PCAP: New Lua Dissector". Pure (no `vscode`
 * import) so it is unit-testable; mirrors the `dissector` snippet.
 */

export interface LuaDissectorSpec {
  /** Protocol short name / filter prefix, e.g. "myproto". */
  name: string;
  /** Human-readable protocol name, e.g. "My Protocol". */
  description: string;
  transport: "udp" | "tcp";
  port: number;
}

const NAME_RE = /^[a-z][a-z0-9_]{0,31}$/;

/** Error message for an invalid protocol short name, or undefined if valid. */
export function validateProtocolName(name: string): string | undefined {
  if (!NAME_RE.test(name)) {
    return "Use 1-32 lowercase letters, digits or _, starting with a letter (it becomes the filter prefix).";
  }
  return undefined;
}

export function validatePort(text: string): string | undefined {
  const n = Number(text);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? undefined : "Enter a port between 1 and 65535.";
}

/** Escape text for a Lua double-quoted string literal. */
function luaString(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\r?\n/g, " ")}"`;
}

export function luaDissectorTemplate(spec: LuaDissectorSpec): string {
  const { name, transport, port } = spec;
  const desc = luaString(spec.description);
  return `-- ${spec.description.replace(/\r?\n/g, " ")} dissector for PCAP Viewer / Wireshark.
--
-- Loaded by tshark as -X lua_script:<this file> (see pcapViewer.dissectorsFolder
-- and pcapViewer.luaScripts). After editing, run "PCAP: Reload Dissectors".
-- Fields defined here can be used in display filters, e.g. ${name}.type == 1.
-- Note: tshark does not load Lua dissectors when running as root.

local ${name} = Proto("${name}", ${desc})

local f_type = ProtoField.uint8("${name}.type", "Type", base.DEC)
local f_length = ProtoField.uint16("${name}.length", "Length", base.DEC)
local f_payload = ProtoField.bytes("${name}.payload", "Payload")
${name}.fields = { f_type, f_length, f_payload }

function ${name}.dissector(buffer, pinfo, tree)
    if buffer:len() < 3 then
        return 0
    end
    pinfo.cols.protocol = ${name}.name

    local subtree = tree:add(${name}, buffer(), ${desc})
    subtree:add(f_type, buffer(0, 1))
    subtree:add(f_length, buffer(1, 2))
    if buffer:len() > 3 then
        subtree:add(f_payload, buffer(3))
    end

    pinfo.cols.info = string.format("Type %d, %d bytes", buffer(0, 1):uint(), buffer:len())
    return buffer:len()
end

DissectorTable.get("${transport}.port"):add(${port}, ${name})
`;
}
