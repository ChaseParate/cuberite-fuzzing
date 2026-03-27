from typing import Callable, Iterable

from boofuzz import (
    Fuzzable,
    FuzzLogger,
    Session,
    Target,
)
from boofuzz.sessions.connection import Connection

from fuzzing.protocol.packets.clientbound import PlayerPositionAndLook, RawPacket

type ClientStatePacketCallback = Callable[
    [bytes, ClientState, Target, FuzzLogger, Session, Fuzzable, Connection], None
]

type ClientStatePreSendCallback = Callable[[ClientState, Session], None]


class ClientState:
    """Client State + Callback Handler
    This class can be passed as a callback to every connection (assuming return data is expected)
    It will use the set handlers for the packet types supported, respond to KeepAlive packets,
    and discard everything else.
    """

    __name__ = "handle_state"

    _packet_callbacks: dict[int, ClientStatePacketCallback] = {}
    _pre_send_callbacks: list[ClientStatePreSendCallback] = []

    compression_threshold: int | None = None
    disconnect_okay: bool = False

    login_player_position_and_look: PlayerPositionAndLook | None = None

    def register_packet_callback(self, id: int, callback: ClientStatePacketCallback):
        self._packet_callbacks[id] = callback

    def unregister_packet_callback(self, id: int):
        self._packet_callbacks.pop(id, None)

    def register_pre_send_callbacks(
        self, callbacks: Iterable[ClientStatePreSendCallback]
    ):
        self._pre_send_callbacks.extend(callbacks)

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

    def on_pre_send(self, session: Session):
        for callback in self._pre_send_callbacks:
            callback(self, session)

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
            callback = self._packet_callbacks.get(packet.id)
            if callback is not None:
                callback(
                    packet.contents, self, target, fuzz_data_logger, session, node, edge
                )
            else:
                fuzz_data_logger.log_info(
                    f"received unknown packet ID {hex(packet.id)}"
                )
