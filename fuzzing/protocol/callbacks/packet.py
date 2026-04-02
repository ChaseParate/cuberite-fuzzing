from boofuzz import Fuzzable, FuzzLogger, Session, Target
from boofuzz.sessions.connection import Connection

from fuzzing.protocol.packets.clientbound import (
    DisconnectLogin,
    DisconnectPlay,
    JoinGame,
    LoginSuccess,
    PlayerListItem,
    PlayerPositionAndLook,
    ServerDifficulty,
    SetCompression,
    SpawnPosition,
)
from fuzzing.protocol.packets.serverbound import create_raw_packet
from fuzzing.protocol.state import ClientState, ServerState


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
    state.state = ServerState.PLAY
    logger.log_info("Logged in successfully")


def handle_disconnect_login(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    disconnect = DisconnectLogin.from_raw_contents(raw)
    logger.log_info(f"Disconnected (login): '{disconnect.reason}'")

    if not state.disconnect_okay:
        logger.log_fail("Received a disconnect packet when one wasn't expected")


def handle_disconnect_play(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    disconnect = DisconnectPlay.from_raw_contents(raw)
    logger.log_info(f"Disconnected (play): '{disconnect.reason}'")

    if not state.disconnect_okay:
        logger.log_fail("Received a disconnect packet when one wasn't expected")


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


def handle_spawn_position(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    spawn_position = SpawnPosition.from_raw_contents(raw)
    logger.log_info(f"Spawn position: '{spawn_position}'")


def handle_server_difficulty(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    server_difficulty = ServerDifficulty.from_raw_contents(raw)
    logger.log_info(f"Server difficulty: '{server_difficulty}'")


def handle_player_list_item(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    player_list_item = PlayerListItem.from_raw_contents(raw)
    logger.log_info(f"Player list item: '{player_list_item}'")


def handle_player_position_and_look(
    raw: bytes,
    state: ClientState,
    target: Target,
    logger: FuzzLogger,
    session: Session,
    node: Fuzzable,
    edge: Connection,
):
    player_position_and_look = PlayerPositionAndLook.from_raw_contents(raw)
    logger.log_info(f"Player position and look: '{player_position_and_look}'")

    state.login_player_position_and_look = player_position_and_look
