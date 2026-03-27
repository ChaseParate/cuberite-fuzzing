from boofuzz import Block, Byte, Float, QWord, Request

from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState


def create_player_position_and_look_packet(state: ClientState) -> Request:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Player_Position_And_Look_.28serverbound.29

    return create_packet(
        "Player Position And Look",
        0xE,
        Block(
            "Data",
            children=(
                # These values will be hot-swapped with the correct value at runtime.
                QWord("x", signed=False, fuzzable=False),
                QWord("y", signed=False, fuzzable=False),
                QWord("z", signed=False, fuzzable=False),
                Float("yaw", encode_as_ieee_754=True, fuzzable=False),
                Float("pitch", encode_as_ieee_754=True, fuzzable=False),
                Byte("on_ground", signed=False),
            ),
        ),
        state.compression_threshold,
    )
