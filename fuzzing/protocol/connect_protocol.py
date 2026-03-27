from boofuzz import Session

from fuzzing.protocol.callbacks.packet import (
    handle_disconnect,
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
from fuzzing.protocol.packets.serverbound.client_settings import (
    create_client_settings_packet,
)
from fuzzing.protocol.packets.serverbound.client_status import (
    create_client_status_packet,
)
from fuzzing.protocol.packets.serverbound.handshake import (
    HANDSHAKE_ANY,
    HANDSHAKE_LOGIN,
)
from fuzzing.protocol.packets.serverbound.login_start import LOGIN_START
from fuzzing.protocol.packets.serverbound.player_position_and_look import (
    create_player_position_and_look_packet,
)
from fuzzing.protocol.packets.serverbound.teleport_confirm import (
    create_teleport_confirm_packet,
)
from fuzzing.protocol.state import ClientState


def connect_protocol(session: Session, state: ClientState) -> None:
    state.register_packet_callback(0x1F, handle_keepalive)
    state.register_packet_callback(0x02, handle_login_success)
    state.register_packet_callback(0x03, handle_set_compression)
    state.register_packet_callback(0x00, handle_disconnect)
    state.register_packet_callback(0x23, handle_join_game)
    state.register_packet_callback(0x46, handle_spawn_position)
    state.register_packet_callback(0x0D, handle_server_difficulty)
    state.register_packet_callback(0x2E, handle_player_list_item)
    state.register_packet_callback(0x2F, handle_player_position_and_look)

    state.register_pre_send_callbacks(
        (update_default_username, update_login_player_position_and_look)
    )

    # Login Sequence: https://c4k3.github.io/wiki.vg/Protocol_FAQ.html#What.27s_the_normal_login_sequence_for_a_client.3F
    session.connect(HANDSHAKE_LOGIN, callback=state.reset())
    session.connect(HANDSHAKE_LOGIN, LOGIN_START)

    client_settings_packet = create_client_settings_packet(state)
    teleport_confirm_packet = create_teleport_confirm_packet(state)
    player_position_and_look_packet = create_player_position_and_look_packet(state)
    client_status_packet = create_client_status_packet(state)
    session.connect(LOGIN_START, client_settings_packet, state)
    session.connect(client_settings_packet, teleport_confirm_packet, state)
    session.connect(teleport_confirm_packet, player_position_and_look_packet, state)
    session.connect(player_position_and_look_packet, client_status_packet, state)
    session.connect(client_status_packet, HANDSHAKE_ANY, state)  # TEMP
