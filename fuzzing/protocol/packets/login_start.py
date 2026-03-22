from boofuzz import BitField, Block, Fuzzable, Request, String, Word

from fuzzing.models.varint_blocks import VarInt, VarIntSized
from fuzzing.protocol import PROTOCOL_VERSION_NUMBER
from fuzzing.protocol.packets import create_packet

# https://minecraft.wiki/w/Java_Edition_protocol/Packets#Login_Start


def create_login_start_packet(fields_fuzzable: bool) -> Request:
    return create_packet(
        "Login Start",
        0,
        Block(
            "login_start_data",
            children=(
                VarIntSized(
                    "name",
                    children=(
                        String(
                            "name_raw",
                            default_value="Boo",
                            max_len=16,
                            fuzzable=fields_fuzzable,
                        ),
                    ),
                ),
                # Cuberite doesn't accept this, for some reason. Maybe this field is only required on later versions?
                # BitField("uuid", width=16, fuzzable=fields_fuzzable),
            ),
        ),
    )


LOGIN_START = create_login_start_packet(True)
