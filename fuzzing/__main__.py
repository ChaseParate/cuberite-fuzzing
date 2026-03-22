from boofuzz import Session, Target, TCPSocketConnection

from fuzzing.protocol.packets.handshake import HANDSHAKE_LOGIN
from fuzzing.protocol.packets.login_start import LOGIN_START


def main():
    session = Session(target=Target(connection=TCPSocketConnection("localhost", 25565)))

    session.connect(HANDSHAKE_LOGIN)
    session.connect(HANDSHAKE_LOGIN, LOGIN_START)
    session.fuzz()


if __name__ == "__main__":
    main()
