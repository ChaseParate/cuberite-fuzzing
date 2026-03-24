import click
from boofuzz import Session, Target, TCPSocketConnection

from fuzzing.listener import MinecraftServer
from fuzzing.protocol.connect_protocol import connect_protocol


@click.command()
@click.option("--port", default=25565, help="port of the Cuberite server")
@click.option("--address", default="localhost", help="address of the server")
def fuzz(port: int, address: str):
    click.echo("running fuzzer")
    session = Session(
        target=Target(
            connection=TCPSocketConnection(address, port),
            monitors=[MinecraftServer(["make", "run-cuberite"])],
        ),
        receive_data_after_each_request=False,
    )

    connect_protocol(session)

    session.fuzz()
