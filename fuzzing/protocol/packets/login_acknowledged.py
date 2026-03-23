from boofuzz import BitField, Block, Fuzzable, Request, String, Word

from fuzzing.models.varint_blocks import VarInt, VarIntSized
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER
from fuzzing.protocol.packets import create_packet

# https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Acknowledged


LOGIN_ACKNOWLEDGED = create_packet("Login Acknowledged", 3, None)
