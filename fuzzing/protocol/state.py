from enum import Enum
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

type ClientStatePreSendCallback = Callable[[ClientState, Session, FuzzLogger], None]


class ServerState(Enum):
    LOGIN = 1
    PLAY = 2


class ClientState:
    """Client State + Callback Handler
    This class can be passed as a callback to every connection (assuming return data is expected)
    It will use the set handlers for the packet types supported, respond to KeepAlive packets,
    and discard everything else.
    """

    __name__ = "handle_state"

    _packet_callbacks: dict[ServerState, dict[int, ClientStatePacketCallback]] = {}
    _pre_send_callbacks: list[ClientStatePreSendCallback] = []

    compression_threshold: int | None = None
    disconnect_okay: bool = False
    state: ServerState = ServerState.LOGIN

    def __init__(self):
        self._packet_callbacks = {
            ServerState.LOGIN: {},
            ServerState.PLAY: {},
        }

    login_player_position_and_look: PlayerPositionAndLook | None = None

    def register_packet_callback(
        self, state: ServerState, id: int, callback: ClientStatePacketCallback
    ):
        self._packet_callbacks[state][id] = callback

    def unregister_packet_callback(self, state: ServerState, id: int):
        self._packet_callbacks[state].pop(id, None)

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
            self.state = ServerState.LOGIN

        return reset_state

    def on_pre_send(self, session: Session, fuzz_data_logger):
        for callback in self._pre_send_callbacks:
            callback(self, session, fuzz_data_logger)

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
            packet, data = RawPacket.read(
                data,
                self.compression_threshold,
                self._packet_callbacks[self.state].keys(),
            )
            if packet is None:
                if len(data) != 0:
                    fuzz_data_logger.log_info("requesting more data")
                    data += target.recv()
                    fuzz_data_logger.log_info("requested more data")
                    continue
                break
            callback = self._packet_callbacks[self.state].get(packet.id)
            if callback is not None:
                fuzz_data_logger.log_info(
                    f"received packet ID {hex(packet.id)} of length {len(packet.contents)}"
                )
                callback(
                    packet.contents, self, target, fuzz_data_logger, session, node, edge
                )
            else:
                fuzz_data_logger.log_info(
                    f"received unknown packet ID {hex(packet.id)} of length {len(packet.contents)}"
                )
        self.on_pre_send(session, fuzz_data_logger)
