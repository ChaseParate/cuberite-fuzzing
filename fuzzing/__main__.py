from boofuzz import Session, Target, TCPSocketConnection

from fuzzing.protocol.connect_protocol import connect_protocol


def main():
    session = Session(
        target=Target(connection=TCPSocketConnection("localhost", 25565)),
        receive_data_after_each_request=False,
    )

    connect_protocol(session)

    session.fuzz()


if __name__ == "__main__":
    main()
