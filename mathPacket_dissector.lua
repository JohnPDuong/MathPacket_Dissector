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

connection = ProtoField.string("mathpacket.connection", "Connection")

mathPacket_protocol.fields = {command, version, operand1, operator, operand2, response_code, result, rounding, overflow}

function doDissection(buffer, pinfo, tree, hexBuffer)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = mathPacket_protocol.name

  local subtree = tree:add(mathPacket_protocol, buffer(), "Math Protocol Data")
  local offset = 0
  local parseLength = parse(" ", buffer, offset)
  local parseString = buffertohex(offset, parseLength, buffer)
  local hexString = string.tohex("CALCULATE")

  if parseString == hexString then
    parseString = buffer(offset, parseLength)
    subtree:add_le(command, parseString)

    offset = parse("/", buffer, offset)
    parseLength = parse("\n", buffer, offset) - offset
    parseString = buffer(offset + 1, parseLength - 1)
    subtree:add_le(version, parseString)

    offset = parse("Operand1: ", buffer, offset)
    parseLength = parse("\n", buffer, offset) - offset
    parseString = buffer(offset + 1, parseLength - 1)
    subtree:add_le(operand1, parseString)

    offset = parse("Operator: ", buffer, offset)
    parseLength = parse("\n", buffer, offset) - offset
    parseString = buffer(offset + 1, parseLength - 1)
    subtree:add_le(operator, parseString)

    offset = parse("Operand2: ", buffer, offset)
    parseLength = parse("\n", buffer, offset) - offset
    parseString = buffer(offset + 1, parseLength - 1)
    subtree:add_le(operand2, parseString)
  else
    offset = parse("/1.0 ", buffer, 0)
    parseLength = parse("\n", buffer, offset) - offset
    parseString = buffer(offset + string.len("/1.0 "), parseLength - string.len("/1.0 "))
    subtree:add_le(response_code, parseString)

    offset = parse("Result: ", buffer, offset)
    parseLength = parse("\n", buffer, offset) - offset
    parseString = buffer(offset + string.len("Result: "), parseLength - string.len("Result: "))
    subtree:add_le(result, parseString)

    offset = parse("Rounding: ", buffer, offset)
    parseLength = parse("\n", buffer, offset) - offset
    parseString = buffer(offset + string.len("Rounding: "), parseLength - string.len("Rounding: "))
    subtree:add_le(rounding, parseString)

    offset = parse("Overflow: ", buffer, offset)
    parseLength = parse("\n", buffer, offset) - offset
    parseString = buffer(offset + string.len("Overflow: "), parseLength - string.len("Overflow: "))
    subtree:add_le(overflow, parseString)
  end
end

function string.tohex(str)
  return (str:gsub('.', function (c)
      return string.format('%02X', string.byte(c))
  end))
end

function parse(parseChar, buffer, offset)
  local pos = offset
  local parseChar = string.tohex(parseChar)

  while parseChar ~= buffer(pos, string.len(parseChar) / 2):bytes():tohex() do
    pos = pos + 1
  end
  
  return pos
end

function buffertohex (offset, length, buffer)
  return buffer(offset, length):bytes():tohex()
end

function mathPacket_protocol.dissector(buffer, pinfo, tree)
  local hexBuffer = buffertohex(0, buffer:len(), buffer)

  if string.find(hexBuffer, "0A0A") then
    doDissection(buffer, pinfo, tree)
  else
    pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
    hexBuffer = buffertohex(0, buffer:len(), buffer)
    doDissection(buffer, pinfo, tree)
  end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8080, mathPacket_protocol)