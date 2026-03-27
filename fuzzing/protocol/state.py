import random
import string
from typing import Callable, Self

from boofuzz import Fuzzable, FuzzLogger, Session, Target
from boofuzz.sessions.connection import Connection

from fuzzing.protocol.packets.clientbound import PlayerPositionAndLook, RawPacket


def _generate_username(*, prefix: str = "Boo_", length: int = 8) -> str:
    return prefix + "".join(
        random.choices(
            string.ascii_letters + string.digits, k=max(length - len(prefix), 0)
        )
    )


class ClientState:
    """Client State + Callback Handler
    This class can be passed as a callback to every connection (assuming return data is expected)
    It will use the set handlers for the packet types supported, respond to KeepAlive packets,
    and discard everything else.
    """

    Callback = Callable[
        [bytes, Self, Target, FuzzLogger, Session, Fuzzable, Connection], None
    ]

    __name__ = "handle_state"

    _callbacks: dict[int, Callback] = {}

    compression_threshold: int | None = None
    disconnect_okay: bool = False

    login_player_position_and_look: PlayerPositionAndLook | None = None

    def register_callback(self, id: int, callback: Callback):
        self._callbacks[id] = callback

    def unregister_callback(self, id: int):
        self._callbacks.pop(id, None)

    def reset(self) -> Callable:
        def reset_state(
            target: Target,
            fuzz_data_logger: FuzzLogger,
            session: Session,
            node: Fuzzable,
            edge: Connection,
            *args,
            **kwargs,
        ):
            fuzz_data_logger.log_info("reset client state")

            self.compression_threshold = None
            self.disconnect_okay = False
            self.login_player_position_and_look = None

        return reset_state

    def pre_send_callback(self, session: Session) -> None:
        # Hack: Update the default username to avoid issues with the player "already being logged in" (likely due to server not cleaning up the user in time for the next test)
        login_start_node = next(
            (node for node in session.nodes.values() if node.name == "Login Start"),
            None,
        )
        if login_start_node is not None:
            username_fuzzable = login_start_node.names[
                "Login Start.length.login_start_data.name.name_raw"
            ]
            username_fuzzable._default_value = _generate_username()

        # Kind of a hack---inject the logged in player position and look data into the relevant packets that require it.
        if self.login_player_position_and_look is not None:
            teleport_confirm_packet = next(
                (
                    node
                    for node in session.nodes.values()
                    if node.name == "Teleport Confirm"
                ),
                None,
            )
            if teleport_confirm_packet is not None:
                teleport_id_fuzzable = teleport_confirm_packet.names[
                    "Teleport Confirm.length.Teleport ID"
                ]
                teleport_id_fuzzable._default_value = (
                    self.login_player_position_and_look.teleport_id
                )

    def __call__(
        self,
        target: Target,
        fuzz_data_logger: FuzzLogger,
        session: Session,
        node: Fuzzable,
        edge: Connection,
        *args,
        **kwargs,
    ):
        data = target.recv()
        while len(data) > 0:
            packet, data = RawPacket.read(data, self.compression_threshold)
            if packet is None:
                if len(data) != 0:
                    fuzz_data_logger.log_error("received incomplete packet")
                break
            callback = self._callbacks.get(packet.id)
            if callback is not None:
                callback(
                    packet.contents, self, target, fuzz_data_logger, session, node, edge
                )
            else:
                fuzz_data_logger.log_info(
                    f"received unknown packet ID {hex(packet.id)}"
                )
