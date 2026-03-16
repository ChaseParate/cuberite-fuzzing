from boofuzz import Session, Target, TCPSocketConnection

from fuzzing.protocol.packets import HANDSHAKE


def main():
    session = Session(target=Target(connection=TCPSocketConnection("localhost", 25565)))

    session.connect(HANDSHAKE)
    session.fuzz()


if __name__ == "__main__":
    main()
