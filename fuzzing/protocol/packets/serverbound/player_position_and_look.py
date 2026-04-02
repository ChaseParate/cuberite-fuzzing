from boofuzz import Block, Byte, Float, QWord, Request

from fuzzing.protocol.packets.serverbound import create_packet
from fuzzing.protocol.state import ClientState


def create_player_position_and_look_packet(
    state: ClientState,
    *,
    fields_fuzzable: bool = True,
    subname: str | None = None,
) -> Request:
    # https://c4k3.github.io/wiki.vg/Protocol.html#Player_Position_And_Look_.28serverbound.29

    name = "Player Position And Look"
    if subname:
        name += f" - {subname}"

    return create_packet(
        name,
        0xE,
        Block(
            "Data",
            children=(
                QWord("x", signed=False, fuzzable=fields_fuzzable),
                QWord("y", signed=False, fuzzable=fields_fuzzable),
                QWord("z", signed=False, fuzzable=fields_fuzzable),
                Float("yaw", encode_as_ieee_754=True, fuzzable=fields_fuzzable),
                Float("pitch", encode_as_ieee_754=True, fuzzable=fields_fuzzable),
                Byte("on_ground", signed=False, fuzzable=fields_fuzzable),
            ),
        ),
        state,
    )
