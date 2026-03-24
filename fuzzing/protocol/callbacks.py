from boofuzz import Fuzzable, FuzzLogger, Session, Target
from boofuzz.sessions.connection import Connection

from fuzzing.protocol.packets.clientbound import (
    Disconnect,
    LoginSuccess,
    SetCompression,
)


def login_success_callback(
    target: Target,
    fuzz_data_logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
    *args,
    **kwargs,
) -> None:
    b = target.recv()
    print(b)

    disconnect, b = Disconnect.from_bytes(b)
    print(disconnect)

    set_compression, b = SetCompression.from_bytes(b)
    print(set_compression)

    login_success, b = LoginSuccess.from_bytes(b)
    print(login_success)
