from typing import Callable, Self

from boofuzz import Fuzzable, FuzzLogger, Session, Target
from boofuzz.sessions.connection import Connection

from fuzzing.protocol.packets.clientbound import read_any_packet


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

    _callbacks: dict[int, Callback]
    compression_threshold: int | None = None

    def __init__(self):
        self._callbacks = {}
        self.compression_threshold = None

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

        return reset_state

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
            packet, data = read_any_packet(data, self.compression_threshold)
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
