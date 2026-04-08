from boofuzz import Request, String

from fuzzing.blocks.varint_blocks import VarIntSized
from fuzzing.protocol.packets.serverbound import create_packet

# https://c4k3.github.io/wiki.vg/Protocol.html#Login_Start


def create_login_start_packet(fields_fuzzable: bool) -> Request:
    return create_packet(
        "Login Start",
        0x0,
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
    )


LOGIN_START = create_login_start_packet(True)
