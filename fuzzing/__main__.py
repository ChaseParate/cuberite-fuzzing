from boofuzz import Session, Target, TCPSocketConnection

from fuzzing.protocol.packets.handshake import HANDSHAKE_LOGIN


def main():
    session = Session(target=Target(connection=TCPSocketConnection("localhost", 25565)))

    session.connect(HANDSHAKE_LOGIN)
    session.fuzz()


if __name__ == "__main__":
    main()
