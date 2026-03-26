from boofuzz import Fuzzable, FuzzLogger, Session, Target
from boofuzz.sessions.connection import Connection

from fuzzing.protocol.packets.clientbound import (
    Disconnect,
    JoinGame,
    LoginSuccess,
    SetCompression,
)
from fuzzing.protocol.packets.serverbound import create_raw_packet
from fuzzing.protocol.state import ClientState


def handle_keepalive(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    logger.log_recv(f"KeepAlive '{raw.hex()}'")
    if len(raw) != 8:
        logger.log_error(
            f"KeepAlive packets should be 8 bytes long. Got {len(raw)} bytes."
        )
    else:
        target.send(create_raw_packet(0x0B, raw, state.compression_threshold))


def handle_login_success(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    # TODO: might want to parse the contents here, doesn't really matter
    login_success = LoginSuccess.from_raw_contents(raw)
    logger.log_info("Logged in successfully")


def handle_disconnect(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    disconnect = Disconnect.from_raw_contents(raw)
    logger.log_info(f"Disconnected: '{disconnect.reason}'")


def handle_set_compression(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    set_compression = SetCompression.from_raw_contents(raw)
    logger.log_info(f"Set compression threshold to {set_compression.threshold}")
    state.compression_threshold = set_compression.threshold


def handle_join_game(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    join_game = JoinGame.from_raw_contents(raw)
    logger.log_info(f"Joined game: '{join_game}'")
