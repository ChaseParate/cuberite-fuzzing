from boofuzz import Session

from fuzzing.protocol.callbacks import login_success_callback
from fuzzing.protocol.packets.serverbound.handshake import (
    HANDSHAKE_ANY,
    HANDSHAKE_LOGIN,
)
from fuzzing.protocol.packets.serverbound.login_acknowledged import LOGIN_ACKNOWLEDGED
from fuzzing.protocol.packets.serverbound.login_start import LOGIN_START


def connect_protocol(session: Session) -> None:
    session.connect(HANDSHAKE_LOGIN)
    session.connect(HANDSHAKE_LOGIN, LOGIN_START)
    session.connect(LOGIN_START, LOGIN_ACKNOWLEDGED, login_success_callback)
    session.connect(LOGIN_ACKNOWLEDGED, HANDSHAKE_ANY)  # TEMP
