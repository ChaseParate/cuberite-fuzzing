from boofuzz import Session, Target, TCPSocketConnection

from fuzzing.protocol.packets.handshake import (
    HANDSHAKE_ANY,
    HANDSHAKE_LOGIN,
)
from fuzzing.protocol.packets.login_acknowledged import LOGIN_ACKNOWLEDGED
from fuzzing.protocol.packets.login_start import LOGIN_START


def main():
    session = Session(target=Target(connection=TCPSocketConnection("localhost", 25565)))

    session.connect(HANDSHAKE_LOGIN)
    session.connect(HANDSHAKE_LOGIN, LOGIN_START)
    session.connect(LOGIN_START, LOGIN_ACKNOWLEDGED)
    session.connect(LOGIN_ACKNOWLEDGED, HANDSHAKE_ANY)  # TEMP

    session.fuzz()


if __name__ == "__main__":
    main()
