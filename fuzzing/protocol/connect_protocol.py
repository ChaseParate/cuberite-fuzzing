from boofuzz import Session

from fuzzing.protocol.callbacks import (
    handle_disconnect,
    handle_join_game,
    handle_keepalive,
    handle_login_success,
    handle_set_compression,
    handle_spawn_position,
)
from fuzzing.protocol.packets.serverbound.handshake import (
    HANDSHAKE_ANY,
    HANDSHAKE_LOGIN,
)
from fuzzing.protocol.packets.serverbound.login_start import LOGIN_START
from fuzzing.protocol.state import ClientState


def connect_protocol(session: Session) -> None:
    state = ClientState()
    state.register_callback(0x1F, handle_keepalive)
    state.register_callback(0x02, handle_login_success)
    state.register_callback(0x03, handle_set_compression)
    state.register_callback(0x00, handle_disconnect)
    state.register_callback(0x23, handle_join_game)
    state.register_callback(0x46, handle_spawn_position)

    # Login Sequence: https://c4k3.github.io/wiki.vg/Protocol_FAQ.html#What.27s_the_normal_login_sequence_for_a_client.3F
    session.connect(HANDSHAKE_LOGIN, callback=state.reset())
    session.connect(HANDSHAKE_LOGIN, LOGIN_START)
    session.connect(LOGIN_START, HANDSHAKE_ANY, state)  # TEMP
