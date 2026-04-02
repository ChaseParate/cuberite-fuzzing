import random
import string
import struct

from boofuzz import Session

from fuzzing.protocol.state import ClientState


def _find_node(session: Session, name: str):
    return next(
        (node for node in session.nodes.values() if node.name == name),
        None,
    )


def _reinterpret_double_float_to_int(f: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", f))[0]


def _generate_username(*, prefix: str = "Boo_", length: int = 8) -> str:
    return prefix + "".join(
        random.choices(
            string.ascii_letters + string.digits, k=max(length - len(prefix), 0)
        )
    )


def update_default_username(state: ClientState, session: Session, _logger):
    login_start_node = _find_node(session, "Login Start")
    if login_start_node is not None:
        login_start_node.names[
            "Login Start.length.login_start_data.name.name_raw"
        ]._default_value = _generate_username()


def update_login_player_position_and_look(state: ClientState, session: Session, logger):
    if state.login_player_position_and_look is not None:
        teleport_confirm_node = _find_node(session, "Teleport Confirm")
        if teleport_confirm_node is not None:
            logger.log_info(
                f"player position and look ID is {state.login_player_position_and_look.teleport_id}"
            )
            teleport_confirm_node.names[
                "Teleport Confirm.length.compressed.Teleport ID"
            ]._default_value = state.login_player_position_and_look.teleport_id
        else:
            logger.log_info("found no teleport confirm :(")

        player_position_and_look_node = _find_node(session, "Player Position And Look")
        if player_position_and_look_node is not None:
            player_position_and_look_node.names[
                "Player Position And Look.length.compressed.Data.x"
            ]._default_value = _reinterpret_double_float_to_int(
                state.login_player_position_and_look.x
            )
            player_position_and_look_node.names[
                "Player Position And Look.length.compressed.Data.y"
            ]._default_value = _reinterpret_double_float_to_int(
                state.login_player_position_and_look.y
            )
            player_position_and_look_node.names[
                "Player Position And Look.length.compressed.Data.z"
            ]._default_value = _reinterpret_double_float_to_int(
                state.login_player_position_and_look.z
            )
            player_position_and_look_node.names[
                "Player Position And Look.length.compressed.Data.yaw"
            ]._default_value = state.login_player_position_and_look.yaw
            player_position_and_look_node.names[
                "Player Position And Look.length.compressed.Data.pitch"
            ]._default_value = state.login_player_position_and_look.pitch
            # player_position_and_look_node.names["Player Position And Look.length.Data.on_ground"]._default_value = ???
