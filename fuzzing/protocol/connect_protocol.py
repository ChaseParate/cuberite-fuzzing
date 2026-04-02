from boofuzz import Request, Session

from fuzzing.protocol.callbacks.packet import (
    handle_disconnect_login,
    handle_disconnect_play,
    handle_join_game,
    handle_keepalive,
    handle_login_success,
    handle_player_list_item,
    handle_player_position_and_look,
    handle_server_difficulty,
    handle_set_compression,
    handle_spawn_position,
)
from fuzzing.protocol.callbacks.pre_send import (
    update_default_username,
    update_login_player_position_and_look,
)
from fuzzing.protocol.packets.serverbound.chat_message import create_chat_message_packet
from fuzzing.protocol.packets.serverbound.client_settings import (
    create_client_settings_packet,
)
from fuzzing.protocol.packets.serverbound.client_status import (
    create_client_status_packet,
)
from fuzzing.protocol.packets.serverbound.handshake import HANDSHAKE_LOGIN
from fuzzing.protocol.packets.serverbound.login_start import LOGIN_START
from fuzzing.protocol.packets.serverbound.player_position_and_look import (
    create_player_position_and_look_packet,
)
from fuzzing.protocol.packets.serverbound.teleport_confirm import (
    create_teleport_confirm_packet,
)
from fuzzing.protocol.state import ClientState, ServerState


def _connect_packets(
    session: Session, state: ClientState, packets: list[Request]
) -> None:
    for packet_1, packet_2 in zip(packets, packets[1:]):
        session.connect(packet_1, packet_2, state)


def connect_login_sequence(session: Session, state: ClientState) -> Request:
    # Login Sequence: https://c4k3.github.io/wiki.vg/Protocol_FAQ.html#What.27s_the_normal_login_sequence_for_a_client.3F

    # TODO: Consider combining these packets into one request?
    session.connect(HANDSHAKE_LOGIN, callback=state.reset())
    session.connect(HANDSHAKE_LOGIN, LOGIN_START)

    client_settings_packet = create_client_settings_packet(state)
    teleport_confirm_packet = create_teleport_confirm_packet(state)
    # The values in this packet will be hot-swapped with the correct value at runtime to fulfill the login sequence.
    player_position_and_look_packet = create_player_position_and_look_packet(
        state,
        fields_fuzzable=False,
        subname="Login",
    )
    client_status_packet = create_client_status_packet(state)

    login_sequence = [
        LOGIN_START,
        client_settings_packet,
        teleport_confirm_packet,
        player_position_and_look_packet,
        client_status_packet,
    ]
    _connect_packets(session, state, login_sequence)

    return login_sequence[-1]


def connect_protocol(session: Session, state: ClientState) -> None:
    state.register_packet_callback(ServerState.PLAY, 0x1F, handle_keepalive)
    state.register_packet_callback(ServerState.LOGIN, 0x02, handle_login_success)
    state.register_packet_callback(ServerState.LOGIN, 0x03, handle_set_compression)
    state.register_packet_callback(ServerState.LOGIN, 0x00, handle_disconnect_login)
    state.register_packet_callback(ServerState.PLAY, 0x1A, handle_disconnect_play)
    state.register_packet_callback(ServerState.PLAY, 0x23, handle_join_game)
    state.register_packet_callback(ServerState.PLAY, 0x46, handle_spawn_position)
    state.register_packet_callback(ServerState.PLAY, 0x0D, handle_server_difficulty)
    state.register_packet_callback(ServerState.PLAY, 0x2E, handle_player_list_item)
    state.register_packet_callback(
        ServerState.PLAY, 0x2F, handle_player_position_and_look
    )

    state.register_pre_send_callbacks(
        (update_default_username, update_login_player_position_and_look)
    )

    final_login_packet = connect_login_sequence(session, state)

    packet_sequences: list[list[Request]] = [
        [create_player_position_and_look_packet(state)],
        [create_chat_message_packet(state)],
    ]

    for packet_sequence in packet_sequences:
        _connect_packets(session, state, [final_login_packet] + packet_sequence)
