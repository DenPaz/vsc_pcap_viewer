-- Example Lua dissector for PCAP Viewer.
--
-- Decodes a toy protocol carried over UDP port 9999:
--   version (1 byte) | type (1 byte) | sequence (2 bytes, big endian) | payload (text)
--
-- Load it by adding its path to `pcapViewer.luaScripts`, or keep it in the
-- dissectors folder (`pcapViewer.dissectorsFolder`). tshark receives it as
-- `-X lua_script:<path>`. Note: tshark refuses to run Lua when started as root.

local example = Proto("example", "Example Protocol")

local msg_types = { [1] = "Hello", [2] = "Data", [3] = "Bye" }

local f_version = ProtoField.uint8("example.version", "Version", base.DEC)
local f_type = ProtoField.uint8("example.type", "Type", base.DEC, msg_types)
local f_seq = ProtoField.uint16("example.seq", "Sequence", base.DEC)
local f_payload = ProtoField.string("example.payload", "Payload")

example.fields = { f_version, f_type, f_seq, f_payload }

function example.dissector(buffer, pinfo, tree)
    if buffer:len() < 4 then
        return 0
    end
    pinfo.cols.protocol = example.name

    local subtree = tree:add(example, buffer(), "Example Protocol Data")
    subtree:add(f_version, buffer(0, 1))
    subtree:add(f_type, buffer(1, 1))
    subtree:add(f_seq, buffer(2, 2))
    if buffer:len() > 4 then
        subtree:add(f_payload, buffer(4))
    end

    local kind = msg_types[buffer(1, 1):uint()] or "Unknown"
    pinfo.cols.info = string.format("%s seq=%d", kind, buffer(2, 2):uint())
    return buffer:len()
end

DissectorTable.get("udp.port"):add(9999, example)
