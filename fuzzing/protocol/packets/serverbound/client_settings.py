from boofuzz import Block, Byte, Request, String

from fuzzing.models.varint_blocks import VarIntBlock, VarIntSized
from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState


def create_client_settings_packet(
    state: ClientState, *, fields_fuzzable: bool = True, enforce_max_length=True
) -> Request:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Client_Settings

    return create_packet(
        "Client Settings",
        0x2,
        Block(
            "client_settings_data",
            children=(
                VarIntSized(
                    "locale",
                    children=(
                        String(
                            "locale_raw",
                            max_len=16 if enforce_max_length else None,
                            fuzzable=fields_fuzzable,
                        ),
                    ),
                ),
                Byte(
                    "view_distance",
                    default_value=8,
                    signed=True,
                    fuzzable=fields_fuzzable,
                ),
                VarIntBlock(
                    "chat_mode", default_value=0, max_num=2, fuzzable=fields_fuzzable
                ),
                Byte(
                    "chat_colors", default_value=0, max_num=1, fuzzable=fields_fuzzable
                ),
                Byte(
                    "displayed_skin_parts",
                    default_value=0,
                    signed=False,
                    fuzzable=fields_fuzzable,
                ),
                VarIntBlock(
                    "main_hand", default_value=0, max_num=1, fuzzable=fields_fuzzable
                ),
            ),
        ),
        state.compression_threshold,
    )
