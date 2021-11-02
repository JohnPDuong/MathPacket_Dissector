mathPacket_protocol = Proto("MATH", "MathPacket Protocol")

command = ProtoField.string("mathpacket.command", "Command", base.ASCII)
version = ProtoField.string("mathpacket.version", "Version", base.ASCII)
operand1 = ProtoField.string("mathpacket.operand1", "Operand 1", base.ASCII)
operator = ProtoField.string("mathpacket.operator", "Operator", base.ASCII)
operand2 = ProtoField.string("mathpacket.operand2", "Operand 2", base.ASCII)

response_code = ProtoField.string("mathpacket.response_code", "Response Code", base.ASCII)
result = ProtoField.string("mathpacket.result", "Result", base.ASCII)
rounding = ProtoField.string("mathpacket.rounding", "Rounding", base.ASCII)
overflow = ProtoField.string("mathpacket.overflow", "Overflow", base.ASCII)

connection = ProtoField.string("mathpacket.connection", "Connection", base.ASCII)

mathPacket_protocol.fields = {command, version, operand1, operator, operand2, response_code, result, rounding, overflow, connection}

function doDissection(buffer, pinfo, tree, hexBuffer)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = mathPacket_protocol.name

  local subtree = tree:add(mathPacket_protocol, buffer(), "Math Protocol Data")
  local offset = 0

  if buffertohex(0, parse(" ", buffer, 0), buffer) == string.tohex("CALCULATE") then
    subtree:add_le(command, buffer(0, parse(" ", buffer, 0)))

    offset = parse("/", buffer, offset)
    subtree:add_le(version, buffer(offset + string.len("/"), parse("\n", buffer, offset) - offset - string.len("/")))

    offset = parse("Operand1: ", buffer, offset)
    subtree:add_le(operand1, buffer(offset + string.len("Operand1: "), parse("\n", buffer, offset) - offset - string.len("Operand1: ")))

    offset = parse("Operator: ", buffer, offset)
    subtree:add_le(operator, buffer(offset + string.len("Operator: "), parse("\n", buffer, offset) - offset - string.len("Operator: ")))

    offset = parse("Operand2: ", buffer, offset)
    subtree:add_le(operand2, buffer(offset + string.len("Operand2: "), parse("\n", buffer, offset) - offset - string.len("Operand2: ")))
  else
    offset = parse("/1.0 ", buffer, 0)
    subtree:add_le(response_code, buffer(offset + string.len("/1.0 "), parse("\n", buffer, offset) - offset - string.len("/1.0 ")))

    offset = parse("Result: ", buffer, offset)
    subtree:add_le(result, buffer(offset + string.len("Result: "), parse("\n", buffer, offset) - offset - string.len("Result: ")))

    offset = parse("Rounding: ", buffer, offset)
    subtree:add_le(rounding, buffer(offset + string.len("Rounding: "), parse("\n", buffer, offset) - offset - string.len("Rounding: ")))

    offset = parse("Overflow: ", buffer, offset)
    subtree:add_le(overflow, buffer(offset + string.len("Overflow: "), parse("\n", buffer, offset) - offset - string.len("Overflow: ")))
  end

  offset = parse("Connection: ", buffer, offset)
  subtree:add_le(connection, buffer(offset + string.len("Connection: "), parse("\n", buffer, offset) - offset - string.len("Connection: ")))
end

function string.tohex(str)
  return (str:gsub('.', function (c)
      return string.format('%02X', string.byte(c))
  end))
end

function parse(parseChar, buffer, offset)
  local pos = offset

  while string.tohex(parseChar) ~= buffer(pos, string.len(string.tohex(parseChar)) / 2):bytes():tohex() do
    pos = pos + 1
  end
  
  return pos
end

function buffertohex (offset, length, buffer)
  return buffer(offset, length):bytes():tohex()
end

function mathPacket_protocol.dissector(buffer, pinfo, tree)
  if not string.find(buffertohex(0, buffer:len(), buffer), "0A0A") then
    pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
  end

  doDissection(buffer, pinfo, tree)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8080, mathPacket_protocol)