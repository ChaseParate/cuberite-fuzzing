from boofuzz import Session

from fuzzing.protocol.callbacks import (
    handle_disconnect,
    handle_keepalive,
    handle_login_success,
    handle_set_compression,
)
from fuzzing.protocol.packets.serverbound.handshake import (
    HANDSHAKE_ANY,
    HANDSHAKE_LOGIN,
)
from fuzzing.protocol.packets.serverbound.login_acknowledged import LOGIN_ACKNOWLEDGED
from fuzzing.protocol.packets.serverbound.login_start import LOGIN_START
from fuzzing.protocol.state import ClientState


def connect_protocol(session: Session) -> None:
    state = ClientState()
    state.register_callback(0x1F, handle_keepalive)
    state.register_callback(0x02, handle_login_success)
    state.register_callback(0x03, handle_set_compression)
    state.register_callback(0x00, handle_disconnect)
    session.connect(HANDSHAKE_LOGIN, callback=state.reset())
    session.connect(HANDSHAKE_LOGIN, LOGIN_START)
    session.connect(LOGIN_START, LOGIN_ACKNOWLEDGED, state)
    session.connect(LOGIN_ACKNOWLEDGED, HANDSHAKE_ANY, state)  # TEMP
