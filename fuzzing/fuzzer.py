import click, shlex
from boofuzz import Session, Target, TCPSocketConnection

from fuzzing.listener import MinecraftServer
from fuzzing.protocol.connect_protocol import connect_protocol
from fuzzing.protocol.state import ClientState


@click.command()
@click.option("--address", default="localhost", help="address of the server")
@click.option("--port", default=25565, help="port of the server")
@click.option("--server-command", default="make run-cuberite", help="command to run to start up the server")
def fuzz(port: int, address: str, server_command: str):
    click.echo("running fuzzer")

    state = ClientState()

    session = Session(
        target=Target(
            connection=TCPSocketConnection(address, port),
            monitors=[MinecraftServer(shlex.split(server_command), address, port, state)],
            max_recv_bytes=2**20,
        ),
        fuzz_loggers=[],
        receive_data_after_each_request=False,
    )

    connect_protocol(session, state)

    session.fuzz()
